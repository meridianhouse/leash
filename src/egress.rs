use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, NetConnection, SecurityEvent, ThreatLevel};
use procfs::process::{FDTarget, Process};
use std::collections::{HashMap, HashSet};
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;

pub struct EgressMonitor {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    prev: HashSet<String>,
}

impl EgressMonitor {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            cfg,
            tx,
            prev: HashSet::new(),
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

                let (pid, name) = inode_to_proc
                    .get(&parsed.inode)
                    .cloned()
                    .unwrap_or_else(|| (0, String::new()));

                let conn = NetConnection {
                    local_addr: parsed.local_addr,
                    local_port: parsed.local_port,
                    remote_addr: parsed.remote_addr,
                    remote_port: parsed.remote_port,
                    state: parsed.state,
                    pid,
                    process_name: name,
                };

                let suspicious = self.cfg.egress.suspicious_ports.contains(&conn.remote_port);
                let level = if suspicious {
                    ThreatLevel::Orange
                } else {
                    ThreatLevel::Green
                };
                let event_type = if suspicious {
                    EventType::NetworkSuspicious
                } else {
                    EventType::NetworkNewConnection
                };

                let mut event = SecurityEvent::new(
                    event_type,
                    level,
                    format!(
                        "Network connection {}:{} -> {}:{} (pid={})",
                        conn.local_addr,
                        conn.local_port,
                        conn.remote_addr,
                        conn.remote_port,
                        conn.pid
                    ),
                );
                event.connection = Some(conn);
                let _ = self.tx.send(mitre::infer_and_tag(event));
            }
        }

        self.prev = seen;
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

fn inode_to_process() -> HashMap<u64, (i32, String)> {
    let mut map = HashMap::new();
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
            .unwrap_or_else(|| String::new());
        let fds = match process.fd() {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                map.entry(inode).or_insert((pid, comm.clone()));
            }
        }
    }

    map
}
