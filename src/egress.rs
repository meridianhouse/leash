use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, NetConnection, SecurityEvent, ThreatLevel};
use nix::libc;
use nu_ansi_term::Color;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;

pub struct EgressMonitor {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    prev: HashSet<String>,
    dns_cache: HashMap<String, Option<String>>,
    known_services: HashMap<String, &'static str>,
    proc_root: String,
    proc_net_tcp_path: String,
    running_in_container: bool,
    warned_container_mode: bool,
}

impl EgressMonitor {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        let running_in_container = is_running_in_container();
        let proc_root = detect_proc_root(running_in_container);
        let proc_net_tcp_path = format!("{proc_root}/net/tcp");
        Self {
            cfg,
            tx,
            prev: HashSet::new(),
            dns_cache: HashMap::new(),
            known_services: known_services_map(),
            proc_root,
            proc_net_tcp_path,
            running_in_container,
            warned_container_mode: false,
        }
    }

    pub async fn run(mut self) {
        loop {
            self.collect_once();
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms)).await;
        }
    }

    fn collect_once(&mut self) {
        if self.running_in_container && !self.warned_container_mode {
            self.warned_container_mode = true;
            warn!(
                proc_root = %self.proc_root,
                "running in container; network visibility is namespace-scoped unless host /proc is mounted"
            );
        }

        let inode_to_proc = inode_to_process(&self.proc_root);
        let lines = match fs::read_to_string(&self.proc_net_tcp_path) {
            Ok(v) => v,
            Err(err) => {
                warn!(?err, path = %self.proc_net_tcp_path, "cannot read proc net tcp file");
                return;
            }
        };

        let mut seen = HashSet::new();

        for line in lines.lines().skip(1) {
            if let Some(parsed) = parse_tcp_line(line) {
                let key = format!(
                    "{}:{}-{}:{}-{}",
                    parsed.local_addr,
                    parsed.local_port,
                    parsed.remote_addr,
                    parsed.remote_port,
                    parsed.inode
                );
                seen.insert(key.clone());

                if self.prev.contains(&key) {
                    continue;
                }

                let (pid, name, cmdline) = inode_to_proc
                    .get(&parsed.inode)
                    .cloned()
                    .unwrap_or_else(|| (0, String::new(), String::new()));

                let conn = NetConnection {
                    local_addr: parsed.local_addr,
                    local_port: parsed.local_port,
                    remote_addr: parsed.remote_addr,
                    remote_port: parsed.remote_port,
                    state: parsed.state,
                    pid,
                    process_name: name,
                };

                let suspicious_reasons = self.suspicious_reasons(&conn, &cmdline);
                let resolved_host = self.resolve_hostname_cached(&conn.remote_addr);
                let service = self.known_service_name(
                    resolved_host.as_deref(),
                    &conn.remote_addr,
                    conn.remote_port,
                );
                let class =
                    self.classify_destination(&conn, &cmdline, &service, &suspicious_reasons);
                let level = class.threat_level();
                let event_type = class.event_type();
                let class_label = class.paint_label();
                let suspicious = !suspicious_reasons.is_empty();

                let narrative = if suspicious {
                    format!(
                        "Suspicious network connection {}:{} -> {}:{}{} (pid={}) service={} class={} reasons=[{}]",
                        conn.local_addr,
                        conn.local_port,
                        conn.remote_addr,
                        conn.remote_port,
                        format_hostname_suffix(&resolved_host),
                        conn.pid,
                        service.as_deref().unwrap_or("unknown"),
                        class_label,
                        suspicious_reasons.join(",")
                    )
                } else {
                    format!(
                        "Network connection {}:{} -> {}:{}{} (pid={}) service={} class={}",
                        conn.local_addr,
                        conn.local_port,
                        conn.remote_addr,
                        conn.remote_port,
                        format_hostname_suffix(&resolved_host),
                        conn.pid,
                        service.as_deref().unwrap_or("unknown"),
                        class_label
                    )
                };
                let mut event = SecurityEvent::new(event_type, level, narrative);
                event.connection = Some(conn);
                let _ = self.tx.send(mitre::infer_and_tag(event));
            }
        }

        self.prev = seen;
    }

    fn classify_destination(
        &self,
        conn: &NetConnection,
        process_cmdline: &str,
        known_service: &Option<String>,
        suspicious_reasons: &[&'static str],
    ) -> DestinationClass {
        if self.cfg.egress.tor_ports.contains(&conn.remote_port)
            || self.cfg.egress.suspicious_ports.contains(&conn.remote_port)
            || self.uses_exfil_service(process_cmdline)
        {
            return DestinationClass::KnownBad;
        }

        if !suspicious_reasons.is_empty() {
            return DestinationClass::KnownBad;
        }

        if known_service.is_some() {
            DestinationClass::KnownGood
        } else {
            DestinationClass::Unknown
        }
    }

    fn resolve_hostname_cached(&mut self, remote_addr: &str) -> Option<String> {
        if let Some(existing) = self.dns_cache.get(remote_addr) {
            return existing.clone();
        }

        let resolved = reverse_dns_lookup(remote_addr);
        self.dns_cache
            .insert(remote_addr.to_string(), resolved.clone());
        resolved
    }

    fn known_service_name(
        &self,
        hostname: Option<&str>,
        remote_addr: &str,
        remote_port: u16,
    ) -> Option<String> {
        if let Some(host) = hostname {
            let lower = host.to_ascii_lowercase();
            if let Some(name) = self.known_services.get(&lower) {
                return Some((*name).to_string());
            }
            if lower.ends_with(".github.com") {
                return Some("GitHub".to_string());
            }
            if lower.ends_with(".openai.com") {
                return Some("OpenAI".to_string());
            }
            if lower.ends_with(".anthropic.com") {
                return Some("Anthropic API".to_string());
            }
        }

        match (remote_addr, remote_port) {
            (_, 443) if remote_addr.starts_with("140.82.") => Some("GitHub".to_string()),
            (_, 443) if remote_addr.starts_with("104.18.") => {
                Some("Cloudflare-hosted API".to_string())
            }
            (_, 443) if remote_addr.starts_with("13.107.") => Some("Microsoft service".to_string()),
            _ => None,
        }
    }

    fn suspicious_reasons(&self, conn: &NetConnection, process_cmdline: &str) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.cfg.egress.suspicious_ports.contains(&conn.remote_port) {
            reasons.push("reverse_shell_port");
        }
        if self.cfg.egress.tor_ports.contains(&conn.remote_port) {
            reasons.push("tor_port");
        }
        if self.is_suspicious_country_ip(&conn.remote_addr) {
            reasons.push("suspicious_country_ip");
        }
        if self.uses_exfil_service(process_cmdline) {
            reasons.push("known_exfil_service");
        }
        reasons
    }

    fn uses_exfil_service(&self, process_cmdline: &str) -> bool {
        let lower = process_cmdline.to_ascii_lowercase();
        self.cfg
            .egress
            .exfil_domains
            .iter()
            .any(|domain| lower.contains(&domain.to_ascii_lowercase()))
    }

    fn is_suspicious_country_ip(&self, remote_addr: &str) -> bool {
        let addr = remote_addr.to_ascii_lowercase();
        self.cfg
            .egress
            .suspicious_country_ip_prefixes
            .iter()
            .map(|item| item.to_ascii_lowercase())
            .any(|item| {
                let prefix = item.trim_end_matches('*');
                addr == prefix || addr.starts_with(prefix)
            })
    }
}

#[derive(Debug, Clone, Copy)]
enum DestinationClass {
    KnownGood,
    Unknown,
    KnownBad,
}

impl DestinationClass {
    fn paint_label(self) -> String {
        match self {
            DestinationClass::KnownGood => Color::Green.bold().paint("KNOWN_GOOD").to_string(),
            DestinationClass::Unknown => Color::Yellow.bold().paint("UNKNOWN").to_string(),
            DestinationClass::KnownBad => Color::Red.bold().paint("KNOWN_BAD").to_string(),
        }
    }

    fn threat_level(self) -> ThreatLevel {
        match self {
            DestinationClass::KnownGood => ThreatLevel::Green,
            DestinationClass::Unknown => ThreatLevel::Yellow,
            DestinationClass::KnownBad => ThreatLevel::Red,
        }
    }

    fn event_type(self) -> EventType {
        match self {
            DestinationClass::KnownBad => EventType::NetworkSuspicious,
            DestinationClass::KnownGood | DestinationClass::Unknown => {
                EventType::NetworkNewConnection
            }
        }
    }
}

#[derive(Debug)]
struct ParsedTcp {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
    inode: u64,
}

fn parse_tcp_line(line: &str) -> Option<ParsedTcp> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 {
        return None;
    }

    let (local_addr, local_port) = parse_addr_port(cols[1])?;
    let (remote_addr, remote_port) = parse_addr_port(cols[2])?;
    let state = cols[3].to_string();
    let inode = cols[9].parse::<u64>().ok()?;

    Some(ParsedTcp {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        inode,
    })
}

fn parse_addr_port(raw: &str) -> Option<(String, u16)> {
    let mut parts = raw.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if addr_hex.len() != 8 {
        return Some(("0.0.0.0".into(), port));
    }

    let bytes = (0..4)
        .map(|i| u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;

    let addr = format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
    Some((addr, port))
}

fn detect_proc_root(running_in_container: bool) -> String {
    if let Ok(root) = std::env::var("LEASH_PROC_ROOT")
        && !root.trim().is_empty()
    {
        return root;
    }

    if running_in_container && Path::new("/host/proc").exists() {
        "/host/proc".to_string()
    } else {
        "/proc".to_string()
    }
}

fn inode_to_process(proc_root: &str) -> HashMap<u64, (i32, String, String)> {
    let mut map: HashMap<u64, (i32, String, String)> = HashMap::new();
    let all = match fs::read_dir(proc_root) {
        Ok(v) => v,
        Err(_) => return map,
    };

    for entry in all {
        let entry = match entry {
            Ok(proc) => proc,
            Err(_) => continue,
        };
        let pid = match entry
            .file_name()
            .to_string_lossy()
            .parse::<i32>()
            .ok()
        {
            Some(pid) => pid,
            None => continue,
        };
        let proc_path = entry.path();
        let comm = fs::read_to_string(proc_path.join("comm"))
            .ok()
            .map(|raw| raw.trim().to_string())
            .unwrap_or_default();
        let cmdline = read_cmdline(proc_path.join("cmdline"));
        let fds = match fs::read_dir(proc_path.join("fd")) {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in fds.flatten() {
            let target = match fs::read_link(fd.path()) {
                Ok(path) => path,
                Err(_) => continue,
            };
            if let Some(inode) = parse_socket_inode(&target) {
                map.entry(inode)
                    .or_insert((pid, comm.clone(), cmdline.clone()));
            }
        }
    }

    map
}

fn read_cmdline(path: std::path::PathBuf) -> String {
    let bytes = match fs::read(path) {
        Ok(raw) => raw,
        Err(_) => return String::new(),
    };

    bytes
        .split(|byte| *byte == 0)
        .filter_map(|part| {
            if part.is_empty() {
                return None;
            }
            std::str::from_utf8(part).ok()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_socket_inode(path: &Path) -> Option<u64> {
    let raw = path.to_string_lossy();
    let inode = raw.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse::<u64>().ok()
}

fn format_hostname_suffix(hostname: &Option<String>) -> String {
    match hostname {
        Some(host) => format!(" ({host})"),
        None => String::new(),
    }
}

fn known_services_map() -> HashMap<String, &'static str> {
    HashMap::from([
        ("api.anthropic.com".to_string(), "Anthropic API"),
        ("api.openai.com".to_string(), "OpenAI API"),
        ("github.com".to_string(), "GitHub"),
        ("api.github.com".to_string(), "GitHub API"),
        ("raw.githubusercontent.com".to_string(), "GitHub Raw"),
    ])
}

fn reverse_dns_lookup(remote_addr: &str) -> Option<String> {
    let ipv4: Ipv4Addr = remote_addr.parse().ok()?;
    let octets = ipv4.octets();
    let mut addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(octets),
        },
        sin_zero: [0; 8],
    };

    let mut host_buf = [0i8; libc::NI_MAXHOST as usize];
    let rc = unsafe {
        libc::getnameinfo(
            (&mut addr as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host_buf.as_mut_ptr(),
            host_buf.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }

    let host = unsafe { CStr::from_ptr(host_buf.as_ptr()) }
        .to_str()
        .ok()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

fn is_running_in_container() -> bool {
    if Path::new("/.dockerenv").exists() {
        return true;
    }

    let cgroup = fs::read_to_string("/proc/1/cgroup").unwrap_or_default();
    ["docker", "containerd", "kubepods", "podman", "lxc"]
        .iter()
        .any(|needle| cgroup.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::EgressMonitor;
    use crate::config::Config;
    use crate::models::{NetConnection, SecurityEvent};
    use tokio::sync::broadcast;

    fn monitor() -> EgressMonitor {
        let cfg = Config::default();
        let (tx, _) = broadcast::channel::<SecurityEvent>(4);
        EgressMonitor::new(cfg, tx)
    }

    fn conn_with_port(port: u16) -> NetConnection {
        NetConnection {
            local_addr: "10.0.0.1".to_string(),
            local_port: 12345,
            remote_addr: "203.0.113.10".to_string(),
            remote_port: port,
            state: "ESTABLISHED".to_string(),
            pid: 999,
            process_name: "python3".to_string(),
        }
    }

    #[test]
    fn reverse_shell_port_detection_flags_4444_and_5555() {
        let monitor = monitor();
        let reasons_4444 = monitor.suspicious_reasons(&conn_with_port(4444), "");
        let reasons_5555 = monitor.suspicious_reasons(&conn_with_port(5555), "");

        assert!(reasons_4444.contains(&"reverse_shell_port"));
        assert!(reasons_5555.contains(&"reverse_shell_port"));
    }

    #[test]
    fn known_good_service_identification_handles_anthropic_api() {
        let monitor = monitor();
        let service = monitor.known_service_name(Some("api.anthropic.com"), "1.1.1.1", 443);
        assert_eq!(service.as_deref(), Some("Anthropic API"));
    }

    #[test]
    fn known_good_service_identification_handles_openai_suffix() {
        let monitor = monitor();
        let service = monitor.known_service_name(Some("api.openai.com"), "1.1.1.1", 443);
        assert_eq!(service.as_deref(), Some("OpenAI API"));
    }

    #[test]
    fn tor_port_range_detection_flags_tor_ports() {
        let monitor = monitor();
        let reasons_9050 = monitor.suspicious_reasons(&conn_with_port(9050), "");
        let reasons_9053 = monitor.suspicious_reasons(&conn_with_port(9053), "");

        assert!(reasons_9050.contains(&"tor_port"));
        assert!(reasons_9053.contains(&"tor_port"));
    }
}
