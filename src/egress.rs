use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, NetConnection, SecurityEvent, ThreatLevel};
use nix::libc;
use nu_ansi_term::Color;
use procfs::process::FDTarget;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::net::Ipv4Addr;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;

pub struct EgressMonitor {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    prev: HashSet<String>,
    dns_cache: HashMap<String, Option<String>>,
    known_services: HashMap<String, &'static str>,
}

impl EgressMonitor {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            cfg,
            tx,
            prev: HashSet::new(),
            dns_cache: HashMap::new(),
            known_services: known_services_map(),
        }
    }

    pub async fn run(mut self) {
        loop {
            self.collect_once();
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms)).await;
        }
    }

    fn collect_once(&mut self) {
        let inode_to_proc = inode_to_process();
        let lines = match std::fs::read_to_string("/proc/net/tcp") {
            Ok(v) => v,
            Err(err) => {
                warn!(?err, "cannot read /proc/net/tcp");
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
                let class = self.classify_destination(&conn, &cmdline, &service, &suspicious_reasons);
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
            (_, 443) if remote_addr.starts_with("104.18.") => Some("Cloudflare-hosted API".to_string()),
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
            DestinationClass::KnownGood | DestinationClass::Unknown => EventType::NetworkNewConnection,
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

fn inode_to_process() -> HashMap<u64, (i32, String, String)> {
    let mut map: HashMap<u64, (i32, String, String)> = HashMap::new();
    let all = match procfs::process::all_processes() {
        Ok(v) => v,
        Err(_) => return map,
    };

    for p in all {
        let process = match p {
            Ok(proc) => proc,
            Err(_) => continue,
        };
        let pid = process.pid;
        let comm = process
            .stat()
            .ok()
            .map(|s| s.comm)
            .unwrap_or_else(String::new);
        let cmdline = process
            .cmdline()
            .ok()
            .map(|parts| parts.join(" "))
            .unwrap_or_default();
        let fds = match process.fd() {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                map.entry(inode)
                    .or_insert((pid, comm.clone(), cmdline.clone()));
            }
        }
    }

    map
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
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}
