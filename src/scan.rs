use crate::config::Config;
use nu_ansi_term::{Color, Style};
use procfs::process::{FDTarget, Process};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use tracing::warn;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Serialize)]
struct ScanReport {
    timestamp: chrono::DateTime<chrono::Utc>,
    ai_agents: Vec<AgentScan>,
}

#[derive(Debug, Serialize)]
struct AgentScan {
    root: ScanProcessSummary,
    process_tree: ScanProcessNode,
    network_connections: Vec<ScanConnection>,
    sensitive_open_files: Vec<ScanSensitiveFd>,
}

#[derive(Debug, Serialize)]
struct ScanProcessSummary {
    pid: i32,
    ppid: i32,
    name: String,
    cmdline: String,
    exe: String,
}

#[derive(Debug, Serialize)]
struct ScanProcessNode {
    pid: i32,
    name: String,
    cmdline: String,
    children: Vec<ScanProcessNode>,
}

#[derive(Debug, Serialize)]
struct ScanConnection {
    pid: i32,
    process_name: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
}

#[derive(Debug, Serialize)]
struct ScanSensitiveFd {
    pid: i32,
    process_name: String,
    path: String,
}

#[derive(Debug, Clone)]
struct ProcessEntry {
    pid: i32,
    ppid: i32,
    name: String,
    cmdline: String,
    exe: String,
}

pub fn run_scan(cfg: Config, json_output: bool) -> Result<(), DynError> {
    let process_table = collect_process_table();
    let children = build_children_map(&process_table);

    let mut roots: Vec<i32> = process_table
        .iter()
        .filter_map(|(pid, process)| is_ai_agent_process(process, &cfg).then_some(*pid))
        .collect();
    roots.sort_unstable();

    let mut ai_agents = Vec::new();

    for root_pid in roots {
        let Some(root_process) = process_table.get(&root_pid) else {
            continue;
        };

        let monitored = collect_descendants(root_pid, &children);
        let process_tree =
            build_scan_tree(root_pid, &process_table, &children).unwrap_or_else(|| {
                ScanProcessNode {
                    pid: root_process.pid,
                    name: root_process.name.clone(),
                    cmdline: root_process.cmdline.clone(),
                    children: Vec::new(),
                }
            });
        let mut network_connections = collect_network_connections(&monitored, &process_table);
        let mut sensitive_open_files =
            collect_sensitive_open_files(&monitored, &process_table, &cfg);

        network_connections.sort_by(|a, b| {
            a.pid
                .cmp(&b.pid)
                .then_with(|| a.remote_addr.cmp(&b.remote_addr))
                .then_with(|| a.remote_port.cmp(&b.remote_port))
        });
        sensitive_open_files.sort_by(|a, b| {
            a.pid
                .cmp(&b.pid)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.process_name.cmp(&b.process_name))
        });

        ai_agents.push(AgentScan {
            root: ScanProcessSummary {
                pid: root_process.pid,
                ppid: root_process.ppid,
                name: root_process.name.clone(),
                cmdline: root_process.cmdline.clone(),
                exe: root_process.exe.clone(),
            },
            process_tree,
            network_connections,
            sensitive_open_files,
        });
    }

    let report = ScanReport {
        timestamp: chrono::Utc::now(),
        ai_agents,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report.ai_agents)?);
    } else {
        render_scan_report(&report);
    }

    Ok(())
}

fn render_scan_report(report: &ScanReport) {
    println!(
        "{}  {}",
        Style::new().bold().paint("LEASH SCAN"),
        report
            .timestamp
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
    );
    println!("{}", "─".repeat(90));

    if report.ai_agents.is_empty() {
        println!("No matching AI agent processes were found.");
        return;
    }

    for agent in &report.ai_agents {
        println!(
            "{} {} ({})",
            Color::Cyan.bold().paint("Agent"),
            Style::new().bold().paint(&agent.root.name),
            agent.root.pid
        );
        println!("  exe: {}", truncate(&agent.root.exe, 80));
        println!("  cmd: {}", truncate(&agent.root.cmdline, 100));
        println!("  tree:");
        render_scan_tree(&agent.process_tree, 2);

        println!("  network:");
        if agent.network_connections.is_empty() {
            println!("    none");
        } else {
            for conn in &agent.network_connections {
                println!(
                    "    {} ({}) {}:{} -> {}:{} [{}]",
                    conn.process_name,
                    conn.pid,
                    conn.local_addr,
                    conn.local_port,
                    conn.remote_addr,
                    conn.remote_port,
                    conn.state
                );
            }
        }

        println!("  sensitive fds:");
        if agent.sensitive_open_files.is_empty() {
            println!("    none");
        } else {
            for fd in &agent.sensitive_open_files {
                println!(
                    "    {} ({}) {}",
                    fd.process_name,
                    fd.pid,
                    truncate(&fd.path, 120)
                );
            }
        }
        println!("{}", Style::new().dimmed().paint("·".repeat(90)));
    }
}

fn render_scan_tree(node: &ScanProcessNode, depth: usize) {
    let indent = " ".repeat(depth * 2);
    println!("{indent}- {} ({})", node.name, node.pid);
    for child in &node.children {
        render_scan_tree(child, depth + 1);
    }
}

fn collect_process_table() -> HashMap<i32, ProcessEntry> {
    let mut table = HashMap::new();
    let all = match procfs::process::all_processes() {
        Ok(all) => all,
        Err(err) => {
            warn!(?err, "unable to enumerate processes for scan");
            return table;
        }
    };

    for process in all {
        let process = match process {
            Ok(process) => process,
            Err(_) => continue,
        };

        let stat = match process.stat() {
            Ok(stat) => stat,
            Err(_) => continue,
        };

        let pid = stat.pid;
        let cmdline = process
            .cmdline()
            .ok()
            .map(|c| c.join(" "))
            .unwrap_or_default();
        let exe = process
            .exe()
            .ok()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        table.insert(
            pid,
            ProcessEntry {
                pid,
                ppid: stat.ppid,
                name: stat.comm,
                cmdline,
                exe,
            },
        );
    }

    table
}

fn is_ai_agent_process(process: &ProcessEntry, cfg: &Config) -> bool {
    let name = process.name.to_ascii_lowercase();
    let cmdline = process.cmdline.to_ascii_lowercase();
    let exe = process.exe.to_ascii_lowercase();

    let configured_match = cfg.ai_agents.iter().any(|agent| {
        let needle = agent.to_ascii_lowercase();
        name.contains(&needle) || cmdline.contains(&needle) || exe.contains(&needle)
    });
    if configured_match {
        return true;
    }

    ["anthropic", "claude-code", "cursor.sh", "opencode"]
        .iter()
        .any(|needle| cmdline.contains(needle) || exe.contains(needle))
}

fn build_children_map(process_table: &HashMap<i32, ProcessEntry>) -> HashMap<i32, Vec<i32>> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for process in process_table.values() {
        children.entry(process.ppid).or_default().push(process.pid);
    }

    for child_list in children.values_mut() {
        child_list.sort_unstable();
    }

    children
}

fn collect_descendants(root_pid: i32, children: &HashMap<i32, Vec<i32>>) -> HashSet<i32> {
    let mut seen = HashSet::new();
    let mut stack = vec![root_pid];

    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        if let Some(kids) = children.get(&pid) {
            for child in kids {
                stack.push(*child);
            }
        }
    }

    seen
}

fn build_scan_tree(
    pid: i32,
    process_table: &HashMap<i32, ProcessEntry>,
    children: &HashMap<i32, Vec<i32>>,
) -> Option<ScanProcessNode> {
    let process = process_table.get(&pid)?;
    let mut node = ScanProcessNode {
        pid: process.pid,
        name: process.name.clone(),
        cmdline: process.cmdline.clone(),
        children: Vec::new(),
    };

    if let Some(kids) = children.get(&pid) {
        for child_pid in kids {
            if let Some(child) = build_scan_tree(*child_pid, process_table, children) {
                node.children.push(child);
            }
        }
    }

    Some(node)
}

fn collect_network_connections(
    monitored: &HashSet<i32>,
    process_table: &HashMap<i32, ProcessEntry>,
) -> Vec<ScanConnection> {
    let socket_owners = collect_socket_owners(monitored, process_table);
    let mut connections = Vec::new();

    let lines = match fs::read_to_string("/proc/net/tcp") {
        Ok(lines) => lines,
        Err(err) => {
            warn!(?err, "cannot read /proc/net/tcp during scan");
            return connections;
        }
    };

    for line in lines.lines().skip(1) {
        let Some(parsed) = parse_tcp_scan_line(line) else {
            continue;
        };
        let Some((pid, process_name)) = socket_owners.get(&parsed.inode) else {
            continue;
        };

        connections.push(ScanConnection {
            pid: *pid,
            process_name: process_name.clone(),
            local_addr: parsed.local_addr,
            local_port: parsed.local_port,
            remote_addr: parsed.remote_addr,
            remote_port: parsed.remote_port,
            state: tcp_state_name(&parsed.state).to_string(),
        });
    }

    connections
}

fn collect_socket_owners(
    monitored: &HashSet<i32>,
    process_table: &HashMap<i32, ProcessEntry>,
) -> HashMap<u64, (i32, String)> {
    let mut owners = HashMap::new();
    let mut pids: Vec<i32> = monitored.iter().copied().collect();
    pids.sort_unstable();

    for pid in pids {
        let process_name = process_table
            .get(&pid)
            .map(|p| p.name.clone())
            .unwrap_or_default();

        let process = match Process::new(pid) {
            Ok(process) => process,
            Err(_) => continue,
        };
        let fds = match process.fd() {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                owners.entry(inode).or_insert((pid, process_name.clone()));
            }
        }
    }

    owners
}

fn collect_sensitive_open_files(
    monitored: &HashSet<i32>,
    process_table: &HashMap<i32, ProcessEntry>,
    cfg: &Config,
) -> Vec<ScanSensitiveFd> {
    let mut findings = Vec::new();
    let mut pids: Vec<i32> = monitored.iter().copied().collect();
    pids.sort_unstable();

    for pid in pids {
        let process_name = process_table
            .get(&pid)
            .map(|p| p.name.clone())
            .unwrap_or_default();
        let process = match Process::new(pid) {
            Ok(process) => process,
            Err(_) => continue,
        };
        let fds = match process.fd() {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in fds.flatten() {
            let FDTarget::Path(path) = fd.target else {
                continue;
            };
            let path = path.display().to_string();
            let path_lc = path.to_ascii_lowercase();
            let matches_sensitive = cfg
                .sensitive_path_keywords
                .iter()
                .any(|keyword| path_lc.contains(&keyword.to_ascii_lowercase()));
            if !matches_sensitive {
                continue;
            }

            findings.push(ScanSensitiveFd {
                pid,
                process_name: process_name.clone(),
                path,
            });
        }
    }

    findings
}

struct ParsedTcpScan {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
    inode: u64,
}

fn parse_tcp_scan_line(line: &str) -> Option<ParsedTcpScan> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 {
        return None;
    }

    let (local_addr, local_port) = parse_ipv4_addr_port(cols[1])?;
    let (remote_addr, remote_port) = parse_ipv4_addr_port(cols[2])?;
    let state = cols[3].to_string();
    let inode = cols[9].parse::<u64>().ok()?;

    Some(ParsedTcpScan {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        inode,
    })
}

fn parse_ipv4_addr_port(raw: &str) -> Option<(String, u16)> {
    let mut parts = raw.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;

    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if addr_hex.len() != 8 {
        return Some(("0.0.0.0".to_string(), port));
    }

    let bytes = (0..4)
        .map(|i| u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;

    Some((
        format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]),
        port,
    ))
}

fn tcp_state_name(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        "0C" => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!(
            "{}...",
            value
                .chars()
                .take(max_len.saturating_sub(3))
                .collect::<String>()
        )
    }
}
