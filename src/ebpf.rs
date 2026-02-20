use crate::mitre;
use crate::models::{EventType, NetConnection, ProcessInfo, SecurityEvent, ThreatLevel};
use crate::stats;
use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use bytes::BytesMut;
use nix::libc;
use procfs::process::Process;
use std::convert::TryInto;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;

const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

const NLMSG_DONE: u16 = 0x3;
const NLMSG_ERROR: u16 = 0x2;

const EBPF_EVENT_EXEC: u32 = 1;
const EBPF_EVENT_EXIT: u32 = 2;
const EBPF_EVENT_OPENAT: u32 = 3;
const EBPF_EVENT_CONNECT: u32 = 4;

const PROC_CONNECTOR_MIN_INTERVAL_MS: u64 = 2_000;
const PROC_CONNECTOR_BUF_SIZE: usize = 4096;
const DEFAULT_TRUSTED_EBPF_OBJECT_PATH: &str = "/usr/lib/leash/leash-ebpf.o";

pub trait KernelMonitor {
    fn attach(&mut self) -> Result<()>;
    fn detach(&mut self) -> Result<()>;
    fn on_event(&mut self, event: &SecurityEvent) -> Result<()>;
}

pub fn attach_kernel_monitor(monitor: &mut dyn KernelMonitor) -> Result<()> {
    monitor.attach()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventSource {
    None,
    ProcConnector,
    Ebpf,
}

#[derive(Debug, Clone)]
pub struct KernelMonitorOptions {
    pub ebpf_object_path: Option<PathBuf>,
    pub proc_connector_protocol: i32,
}

impl Default for KernelMonitorOptions {
    fn default() -> Self {
        Self {
            ebpf_object_path: debug_ebpf_override_path(),
            proc_connector_protocol: NETLINK_CONNECTOR,
        }
    }
}

pub struct KernelMonitorRuntime {
    pub source: KernelEventSource,
    pub process_events_active: bool,
    handle: Option<JoinHandle<()>>,
}

impl KernelMonitorRuntime {
    pub fn none() -> Self {
        Self {
            source: KernelEventSource::None,
            process_events_active: false,
            handle: None,
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

pub fn proc_connector_poll_interval_override_ms(base_interval_ms: u64) -> u64 {
    base_interval_ms.max(PROC_CONNECTOR_MIN_INTERVAL_MS)
}

pub fn spawn_kernel_monitor(
    tx: broadcast::Sender<SecurityEvent>,
    prefer_ebpf: bool,
) -> KernelMonitorRuntime {
    spawn_kernel_monitor_with_options(tx, prefer_ebpf, KernelMonitorOptions::default())
}

pub fn spawn_kernel_monitor_with_options(
    tx: broadcast::Sender<SecurityEvent>,
    prefer_ebpf: bool,
    options: KernelMonitorOptions,
) -> KernelMonitorRuntime {
    if prefer_ebpf {
        match spawn_ebpf_task(tx.clone(), options.ebpf_object_path.clone()) {
            Ok(handle) => {
                info!("kernel monitor active: eBPF tracepoints");
                return KernelMonitorRuntime {
                    source: KernelEventSource::Ebpf,
                    process_events_active: true,
                    handle: Some(handle),
                };
            }
            Err(err) => {
                warn!(
                    ?err,
                    "eBPF monitor unavailable; falling back to proc connector"
                );
            }
        }
    }

    if !prefer_ebpf {
        // Only try kernel-level monitoring when explicitly requested
        return KernelMonitorRuntime::none();
    }

    match ProcConnectorMonitor::new(tx, options.proc_connector_protocol) {
        Ok(monitor) => {
            let handle = tokio::task::spawn_blocking(move || {
                if let Err(err) = monitor.run() {
                    warn!(?err, "proc connector monitor exited");
                }
            });
            info!("kernel monitor active: proc connector netlink");
            KernelMonitorRuntime {
                source: KernelEventSource::ProcConnector,
                process_events_active: true,
                handle: Some(handle),
            }
        }
        Err(err) => {
            warn!(
                ?err,
                "kernel event monitor disabled; continuing with /proc polling"
            );
            KernelMonitorRuntime::none()
        }
    }
}

#[derive(Default)]
pub struct EbpfMonitor {
    bpf: Option<Ebpf>,
    object_path: Option<PathBuf>,
}

impl KernelMonitor for EbpfMonitor {
    fn attach(&mut self) -> Result<()> {
        let object_path = resolve_ebpf_object(self.object_path.clone())?;
        let mut bpf = Ebpf::load_file(&object_path)
            .with_context(|| format!("failed loading eBPF object {}", object_path.display()))?;
        attach_tracepoints(&mut bpf)?;
        self.bpf = Some(bpf);
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        self.bpf.take();
        Ok(())
    }

    fn on_event(&mut self, _event: &SecurityEvent) -> Result<()> {
        Ok(())
    }
}

fn spawn_ebpf_task(
    tx: broadcast::Sender<SecurityEvent>,
    object_path: Option<PathBuf>,
) -> Result<JoinHandle<()>> {
    let path = resolve_ebpf_object(object_path)?;
    let mut bpf = Ebpf::load_file(&path)
        .with_context(|| format!("failed loading eBPF object {}", path.display()))?;
    attach_tracepoints(&mut bpf)?;

    let events_map = bpf.take_map("EVENTS").ok_or_else(|| anyhow::anyhow!("missing EVENTS map"))?;
    let mut perf_array =
        AsyncPerfEventArray::try_from(events_map)
            .context("failed to open EVENTS perf array")?;

    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{msg}: {e}"))?;
    let mut readers = Vec::new();
    for cpu in cpus {
        let buf = perf_array
            .open(cpu, None)
            .with_context(|| format!("open perf buffer for cpu {cpu}"))?;
        readers.push((cpu, buf));
    }

    Ok(tokio::spawn(async move {
        let mut tasks = Vec::new();
        for (cpu, mut buf) in readers {
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                let mut buffers = (0..16)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    match buf.read_events(&mut buffers).await as Result<aya::maps::perf::Events, _> {
                        Ok(events) => {
                            for slot in buffers.iter().take(events.read) {
                                if let Some(event) = parse_ebpf_event(slot) {
                                    send_event(&tx, event);
                                }
                            }
                            for slot in buffers.iter_mut() {
                                slot.clear();
                            }
                        }
                        Err(err) => {
                            error!(?err, cpu, "error reading eBPF perf events");
                            break;
                        }
                    }
                }
            }));
        }

        for task in tasks {
            if let Err(err) = task.await {
                warn!(?err, "eBPF cpu reader task join error");
            }
        }

        drop(bpf);
    }))
}

fn resolve_ebpf_object(path: Option<PathBuf>) -> Result<PathBuf> {
    let path = path.unwrap_or_else(|| PathBuf::from(DEFAULT_TRUSTED_EBPF_OBJECT_PATH));
    if !path.exists() {
        anyhow::bail!("eBPF object not found at {}", path.display());
    }
    validate_ebpf_object_file(&path)?;
    Ok(path)
}

#[cfg(debug_assertions)]
fn debug_ebpf_override_path() -> Option<PathBuf> {
    std::env::var("LEASH_EBPF_OBJECT").ok().map(PathBuf::from)
}

#[cfg(not(debug_assertions))]
fn debug_ebpf_override_path() -> Option<PathBuf> {
    None
}

fn validate_ebpf_object_file(path: &PathBuf) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat eBPF object {}", path.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("eBPF object must be a regular file: {}", path.display());
    }
    let uid = metadata.uid();
    let current_uid = unsafe { libc::geteuid() };
    if uid != current_uid && uid != 0 {
        anyhow::bail!(
            "eBPF object owner must be current user ({}) or root (0), got {} for {}",
            current_uid,
            uid,
            path.display()
        );
    }
    let mode = metadata.mode();
    if mode & 0o002 != 0 {
        anyhow::bail!(
            "eBPF object is world-writable and untrusted: {} (mode {:o})",
            path.display(),
            mode & 0o7777
        );
    }
    Ok(())
}

fn attach_tracepoints(bpf: &mut Ebpf) -> Result<()> {
    attach_tracepoint_program(
        bpf,
        "trace_sched_process_exec",
        "sched",
        "sched_process_exec",
    )?;
    attach_tracepoint_program(
        bpf,
        "trace_sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;
    attach_tracepoint_program(
        bpf,
        "trace_sys_enter_openat",
        "syscalls",
        "sys_enter_openat",
    )?;
    attach_tracepoint_program(
        bpf,
        "trace_sys_enter_connect",
        "syscalls",
        "sys_enter_connect",
    )?;
    Ok(())
}

fn attach_tracepoint_program(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    tracepoint: &str,
) -> Result<()> {
    let program = bpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow::anyhow!("missing tracepoint program: {program_name}"))?;
    let program: &mut TracePoint = program
        .try_into()
        .with_context(|| format!("{program_name} is not a tracepoint program"))?;
    program
        .load()
        .with_context(|| format!("failed to load {program_name}"))?;
    program
        .attach(category, tracepoint)
        .with_context(|| format!("failed to attach {program_name} to {category}/{tracepoint}"))?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcEvent {
    Fork {
        parent_pid: i32,
        child_pid: i32,
    },
    Exec {
        pid: i32,
    },
    Exit {
        pid: i32,
        exit_code: i32,
        exit_signal: i32,
    },
}

struct ProcConnectorMonitor {
    tx: broadcast::Sender<SecurityEvent>,
    protocol: i32,
}

impl ProcConnectorMonitor {
    fn new(tx: broadcast::Sender<SecurityEvent>, protocol: i32) -> Result<Self> {
        let monitor = Self { tx, protocol };
        monitor.probe()?;
        Ok(monitor)
    }

    fn probe(&self) -> Result<()> {
        let fd = open_proc_connector_socket(self.protocol)?;
        if let Err(err) = set_proc_connector_subscription(fd, true) {
            // SAFETY: fd was opened by socket(2).
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        set_proc_connector_subscription(fd, false).ok();
        // SAFETY: fd was opened by socket(2).
        unsafe {
            libc::close(fd);
        }
        Ok(())
    }

    fn run(self) -> Result<()> {
        let fd = open_proc_connector_socket(self.protocol)?;
        set_proc_connector_subscription(fd, true)?;

        let mut buf = vec![0_u8; PROC_CONNECTOR_BUF_SIZE];
        loop {
            // SAFETY: fd is valid and buf is writable.
            let received = unsafe {
                libc::recv(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_CMSG_CLOEXEC,
                )
            };
            if received < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                warn!(?err, "proc connector recv failed");
                break;
            }
            if received == 0 {
                continue;
            }

            let packet = &buf[..received as usize];
            for proc_event in parse_proc_connector_events(packet) {
                if let Some(event) = security_event_from_proc_event(proc_event) {
                    send_event(&self.tx, event);
                }
            }
        }

        set_proc_connector_subscription(fd, false).ok();
        // SAFETY: fd was opened by socket(2).
        unsafe {
            libc::close(fd);
        }
        Ok(())
    }
}

fn open_proc_connector_socket(protocol: i32) -> Result<RawFd> {
    // SAFETY: socket call has no Rust-side preconditions.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open netlink connector socket");
    }

    // SAFETY: zeroed is valid for sockaddr_nl.
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = CN_IDX_PROC;

    // SAFETY: addr points to initialized sockaddr_nl.
    let bind_result = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bind_result != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: fd was opened by socket(2).
        unsafe {
            libc::close(fd);
        }
        return Err(err).context("bind netlink connector socket");
    }

    Ok(fd)
}

fn set_proc_connector_subscription(fd: RawFd, subscribe: bool) -> Result<()> {
    // SAFETY: zeroed is valid for nlmsghdr.
    let mut nlh: libc::nlmsghdr = unsafe { mem::zeroed() };
    // SAFETY: zeroed is valid for sockaddr_nl.
    let mut kern_addr: libc::sockaddr_nl = unsafe { mem::zeroed() };

    let op = if subscribe {
        PROC_CN_MCAST_LISTEN
    } else {
        PROC_CN_MCAST_IGNORE
    };

    let cn_msg_len = 20_usize;
    let payload_len = mem::size_of::<u32>();
    let total_len = mem::size_of::<libc::nlmsghdr>() + cn_msg_len + payload_len;

    let mut buf = vec![0_u8; total_len];

    nlh.nlmsg_len = total_len as u32;
    nlh.nlmsg_type = NLMSG_DONE;
    nlh.nlmsg_flags = 0;
    nlh.nlmsg_pid = 0;
    nlh.nlmsg_seq = 0;

    kern_addr.nl_family = libc::AF_NETLINK as u16;
    kern_addr.nl_pid = 0;
    kern_addr.nl_groups = 0;

    // SAFETY: writing nlh bytes into backing buffer with exact size.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &nlh as *const libc::nlmsghdr as *const u8,
            buf.as_mut_ptr(),
            mem::size_of::<libc::nlmsghdr>(),
        );
    }

    let mut offset = mem::size_of::<libc::nlmsghdr>();
    write_u32(&mut buf, offset, CN_IDX_PROC);
    offset += 4;
    write_u32(&mut buf, offset, CN_VAL_PROC);
    offset += 4;
    write_u32(&mut buf, offset, 0);
    offset += 4;
    write_u32(&mut buf, offset, 0);
    offset += 4;
    write_u16(&mut buf, offset, payload_len as u16);
    offset += 2;
    write_u16(&mut buf, offset, 0);
    offset += 2;
    write_u32(&mut buf, offset, op);

    // SAFETY: arguments are valid and buffer points to initialized memory.
    let sent = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            &kern_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        return Err(io::Error::last_os_error())
            .context("set proc connector multicast subscription");
    }

    Ok(())
}

fn parse_proc_connector_events(packet: &[u8]) -> Vec<ProcEvent> {
    let mut events = Vec::new();
    let mut cursor = 0usize;

    while cursor + mem::size_of::<libc::nlmsghdr>() <= packet.len() {
        let header_bytes = &packet[cursor..cursor + mem::size_of::<libc::nlmsghdr>()];
        let nlmsg_len = read_u32(header_bytes, 0).unwrap_or(0) as usize;
        if nlmsg_len < mem::size_of::<libc::nlmsghdr>() || cursor + nlmsg_len > packet.len() {
            break;
        }

        let nlmsg_type = read_u16(header_bytes, 4).unwrap_or(0);
        if nlmsg_type == NLMSG_ERROR {
            break;
        }

        let payload = &packet[cursor + mem::size_of::<libc::nlmsghdr>()..cursor + nlmsg_len];

        if let Some(proc_event) = parse_proc_connector_payload(payload) {
            events.push(proc_event);
        }

        cursor += nlmsg_align(nlmsg_len);
    }

    events
}

fn parse_proc_connector_payload(payload: &[u8]) -> Option<ProcEvent> {
    if payload.len() < 20 + 16 {
        return None;
    }

    let cn_len = read_u16(payload, 16)? as usize;
    if cn_len < 16 || payload.len() < 20 + cn_len {
        return None;
    }

    parse_proc_event_payload(&payload[20..20 + cn_len])
}

fn parse_proc_event_payload(payload: &[u8]) -> Option<ProcEvent> {
    if payload.len() < 16 {
        return None;
    }

    let what = read_u32(payload, 0)?;

    match what {
        PROC_EVENT_FORK if payload.len() >= 32 => {
            let parent_pid = read_u32(payload, 16)? as i32;
            let child_pid = read_u32(payload, 24)? as i32;
            Some(ProcEvent::Fork {
                parent_pid,
                child_pid,
            })
        }
        PROC_EVENT_EXEC if payload.len() >= 24 => {
            let pid = read_u32(payload, 16)? as i32;
            Some(ProcEvent::Exec { pid })
        }
        PROC_EVENT_EXIT if payload.len() >= 32 => {
            let pid = read_u32(payload, 16)? as i32;
            let exit_code = read_u32(payload, 24)? as i32;
            let exit_signal = read_u32(payload, 28)? as i32;
            Some(ProcEvent::Exit {
                pid,
                exit_code,
                exit_signal,
            })
        }
        _ => None,
    }
}

fn security_event_from_proc_event(proc_event: ProcEvent) -> Option<SecurityEvent> {
    match proc_event {
        ProcEvent::Fork {
            parent_pid,
            child_pid,
        } => {
            let process = read_process_info(child_pid, Some(parent_pid));
            let process_name = process
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let mut event = SecurityEvent::new(
                EventType::ProcessNew,
                ThreatLevel::Green,
                format!(
                    "Process fork detected: parent PID {} -> child PID {} ({})",
                    parent_pid, child_pid, process_name
                ),
            );
            event.process = process;
            Some(mitre::infer_and_tag(event))
        }
        ProcEvent::Exec { pid } => {
            let process = read_process_info(pid, None);
            let process_name = process
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let mut event = SecurityEvent::new(
                EventType::ProcessNew,
                ThreatLevel::Green,
                format!("Process exec detected: PID {} ({})", pid, process_name),
            );
            event.process = process;
            Some(mitre::infer_and_tag(event))
        }
        ProcEvent::Exit {
            pid,
            exit_code,
            exit_signal,
        } => {
            let mut event = SecurityEvent::new(
                EventType::ProcessExit,
                ThreatLevel::Green,
                format!(
                    "Process exit detected: PID {} (exit_code={}, signal={})",
                    pid, exit_code, exit_signal
                ),
            );
            event.process = read_process_info(pid, None);
            Some(mitre::infer_and_tag(event))
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawEbpfEvent {
    kind: u32,
    pid: u32,
    ppid: u32,
    flags: u32,
    addr: u32,
    port: u16,
    _reserved: u16,
    comm: [u8; 16],
    filename: [u8; 256],
}

fn parse_ebpf_event(buf: &[u8]) -> Option<SecurityEvent> {
    if buf.len() < mem::size_of::<RawEbpfEvent>() {
        return None;
    }

    // SAFETY: buf size is validated above and perf buffers are not guaranteed to be naturally
    // aligned for RawEbpfEvent, so an unaligned read is required here.
    let raw = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const RawEbpfEvent) };

    let comm = c_bytes_to_string(&raw.comm);
    let filename = c_bytes_to_string(&raw.filename);

    match raw.kind {
        EBPF_EVENT_EXEC => {
            let mut event = SecurityEvent::new(
                EventType::ProcessNew,
                ThreatLevel::Green,
                format!(
                    "eBPF exec: pid={} ppid={} comm={} file={}",
                    raw.pid, raw.ppid, comm, filename
                ),
            );
            event.process = Some(process_info_from_ebpf(
                raw.pid as i32,
                raw.ppid as i32,
                &comm,
                &filename,
            ));
            Some(mitre::infer_and_tag(event))
        }
        EBPF_EVENT_EXIT => {
            let mut event = SecurityEvent::new(
                EventType::ProcessExit,
                ThreatLevel::Green,
                format!("eBPF exit: pid={} comm={}", raw.pid, comm),
            );
            event.process = Some(process_info_from_ebpf(
                raw.pid as i32,
                raw.ppid as i32,
                &comm,
                "",
            ));
            Some(mitre::infer_and_tag(event))
        }
        EBPF_EVENT_OPENAT => {
            if !looks_sensitive_path(&filename) {
                return None;
            }
            let mut event = SecurityEvent::new(
                EventType::CredentialAccess,
                ThreatLevel::Orange,
                format!(
                    "eBPF openat sensitive path: pid={} comm={} path={} flags=0x{:x}",
                    raw.pid, comm, filename, raw.flags
                ),
            );
            event.process = Some(process_info_from_ebpf(
                raw.pid as i32,
                raw.ppid as i32,
                &comm,
                "",
            ));
            Some(mitre::infer_and_tag(event))
        }
        EBPF_EVENT_CONNECT => {
            let addr = std::net::Ipv4Addr::from(raw.addr).to_string();
            let mut event = SecurityEvent::new(
                EventType::NetworkNewConnection,
                ThreatLevel::Yellow,
                format!(
                    "eBPF connect: pid={} comm={} remote={}:{}",
                    raw.pid, comm, addr, raw.port
                ),
            );
            event.process = Some(process_info_from_ebpf(
                raw.pid as i32,
                raw.ppid as i32,
                &comm,
                "",
            ));
            event.connection = Some(NetConnection {
                local_addr: "0.0.0.0".to_string(),
                local_port: 0,
                remote_addr: addr,
                remote_port: raw.port,
                state: "connect".to_string(),
                pid: raw.pid as i32,
                process_name: comm,
            });
            Some(mitre::infer_and_tag(event))
        }
        _ => None,
    }
}

fn process_info_from_ebpf(pid: i32, ppid: i32, comm: &str, exe: &str) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid,
        name: comm.to_string(),
        cmdline: comm.to_string(),
        exe: exe.to_string(),
        cwd: String::new(),
        username: String::new(),
        open_files: Vec::new(),
        parent_chain: Vec::new(),
        start_time: None,
    }
}

fn looks_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".ssh",
        ".gnupg",
        "id_rsa",
        "id_ed25519",
        "shadow",
        "sudoers",
        "kube",
        "aws",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn read_process_info(pid: i32, ppid_hint: Option<i32>) -> Option<ProcessInfo> {
    let proc = Process::new(pid).ok()?;
    let stat = proc.stat().ok();
    let name = stat
        .as_ref()
        .map(|s| s.comm.clone())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let ppid = ppid_hint.or_else(|| stat.map(|s| s.ppid)).unwrap_or(0);

    let cmdline = proc
        .cmdline()
        .ok()
        .map(|parts| parts.join(" "))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| name.clone());

    let exe = proc
        .exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let cwd = proc
        .cwd()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let username = proc
        .status()
        .ok()
        .map(|s| s.ruid.to_string())
        .unwrap_or_default();

    Some(ProcessInfo {
        pid,
        ppid,
        name,
        cmdline,
        exe,
        cwd,
        username,
        open_files: Vec::new(),
        parent_chain: Vec::new(),
        start_time: None,
    })
}

fn c_bytes_to_string(buf: &[u8]) -> String {
    let nul = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul]).trim().to_string()
}

fn send_event(tx: &broadcast::Sender<SecurityEvent>, event: SecurityEvent) {
    if let Err(err) = tx.send(event) {
        stats::record_dropped_event();
        debug!(event_type = %err.0.event_type, "dropping event from kernel monitor");
    }
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    let end = offset.saturating_add(2);
    if end <= buf.len() {
        buf[offset..end].copy_from_slice(&value.to_ne_bytes());
    }
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    let end = offset.saturating_add(4);
    if end <= buf.len() {
        buf[offset..end].copy_from_slice(&value.to_ne_bytes());
    }
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes(bytes.try_into().ok()?))
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

fn nlmsg_align(len: usize) -> usize {
    let align_to = 4usize;
    (len + align_to - 1) & !(align_to - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventType;

    fn header_and_cn(proc_payload: &[u8]) -> Vec<u8> {
        let nl_len = mem::size_of::<libc::nlmsghdr>() + 20 + proc_payload.len();
        let mut out = vec![0_u8; nl_len];

        write_u32(&mut out, 0, nl_len as u32);
        write_u16(&mut out, 4, NLMSG_DONE);

        let mut offset = mem::size_of::<libc::nlmsghdr>();
        write_u32(&mut out, offset, CN_IDX_PROC);
        offset += 4;
        write_u32(&mut out, offset, CN_VAL_PROC);
        offset += 4;
        write_u32(&mut out, offset, 0);
        offset += 4;
        write_u32(&mut out, offset, 0);
        offset += 4;
        write_u16(&mut out, offset, proc_payload.len() as u16);
        offset += 2;
        write_u16(&mut out, offset, 0);
        offset += 2;
        out[offset..offset + proc_payload.len()].copy_from_slice(proc_payload);

        out
    }

    #[test]
    fn parses_exec_proc_event_payload() {
        let mut payload = vec![0_u8; 24];
        write_u32(&mut payload, 0, PROC_EVENT_EXEC);
        write_u32(&mut payload, 16, 4242);
        write_u32(&mut payload, 20, 4242);

        let parsed = parse_proc_event_payload(&payload);
        assert_eq!(parsed, Some(ProcEvent::Exec { pid: 4242 }));
    }

    #[test]
    fn parses_exit_from_netlink_packet() {
        let mut proc_payload = vec![0_u8; 32];
        write_u32(&mut proc_payload, 0, PROC_EVENT_EXIT);
        write_u32(&mut proc_payload, 16, 9001);
        write_u32(&mut proc_payload, 24, 17);
        write_u32(&mut proc_payload, 28, 9);

        let packet = header_and_cn(&proc_payload);
        let events = parse_proc_connector_events(&packet);

        assert_eq!(
            events,
            vec![ProcEvent::Exit {
                pid: 9001,
                exit_code: 17,
                exit_signal: 9
            }]
        );
    }

    #[test]
    fn proc_event_maps_to_security_event_type() {
        let event = security_event_from_proc_event(ProcEvent::Exec { pid: 1234 })
            .expect("exec event should map");
        assert_eq!(event.event_type, EventType::ProcessNew);
        assert!(event.narrative.contains("exec"));
    }

    #[test]
    fn poll_interval_override_never_below_proc_connector_floor() {
        assert_eq!(proc_connector_poll_interval_override_ms(100), 2_000);
        assert_eq!(proc_connector_poll_interval_override_ms(5_000), 5_000);
    }
}
