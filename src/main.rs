mod alerts;
mod cli;
mod collector;
mod config;
mod egress;
mod fim;
mod mitre;
mod models;
mod response;
mod watchdog;

use crate::alerts::AlertDispatcher;
use crate::cli::{Cli, Commands};
use crate::collector::ProcessCollector;
use crate::config::Config;
use crate::egress::EgressMonitor;
use crate::fim::FileIntegrityMonitor;
use crate::mitre::infer_and_tag;
use crate::models::{EventType, FileEvent, NetConnection, ProcessInfo, SecurityEvent, ThreatLevel};
use crate::response::ResponseEngine;
use crate::watchdog::Watchdog;
use clap::Parser;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nu_ansi_term::{AnsiString, Color, Style};
use procfs::process::{FDTarget, Process};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;
use tokio::time::{Duration, interval, sleep};
use tracing::{debug, error, info, warn};

const PID_FILE: &str = "/tmp/leash.pid";

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            init_config(cli.json)?;
        }
        Commands::Start => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, false, cli.json).await?;
        }
        Commands::Watch => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, true, cli.json).await?;
        }
        Commands::Test => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_test_alerts(cfg, cli.json).await?;
        }
        Commands::Scan => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_scan(cfg, cli.json)?;
        }
        Commands::Status => {
            print_status(cli.json)?;
        }
        Commands::Stop => {
            stop_agent(cli.json)?;
        }
    }

    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "leash=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

async fn run_agent(cfg: Config, watch_mode: bool, json_output: bool) -> Result<(), DynError> {
    ensure_single_instance()?;
    write_pid_file()?;

    if !json_output {
        print_startup_banner();
    }

    let (event_tx, _) = broadcast::channel::<SecurityEvent>(8_192);
    let collector = ProcessCollector::new(cfg.clone(), event_tx.clone());
    let egress = EgressMonitor::new(cfg.clone(), event_tx.clone());
    let fim = FileIntegrityMonitor::new(cfg.clone(), event_tx.clone())?;
    let alerts = AlertDispatcher::new(cfg.clone(), event_tx.subscribe())?;
    let response = ResponseEngine::new(cfg.clone(), event_tx.subscribe());
    let watchdog = Watchdog::new(cfg.clone(), event_tx.clone());

    let watch_handle = if watch_mode {
        Some(tokio::spawn(watch_events(
            event_tx.subscribe(),
            json_output,
        )))
    } else {
        None
    };

    let collector_handle = tokio::spawn(async move { collector.run().await });
    let egress_handle = tokio::spawn(async move { egress.run().await });
    let fim_handle = tokio::spawn(async move { fim.run().await });
    let alerts_handle = tokio::spawn(async move { alerts.run().await });
    let response_handle = tokio::spawn(async move { response.run().await });
    let watchdog_handle = tokio::spawn(async move { watchdog.run().await });

    info!("Leash is running. Press Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutdown requested.");

    let _ = collector_handle.abort();
    let _ = egress_handle.abort();
    let _ = fim_handle.abort();
    let _ = alerts_handle.abort();
    let _ = response_handle.abort();
    let _ = watchdog_handle.abort();
    if let Some(handle) = watch_handle {
        let _ = handle.abort();
    }

    cleanup_pid_file();
    Ok(())
}

async fn watch_events(mut rx: broadcast::Receiver<SecurityEvent>, json_output: bool) {
    let mut ticker = interval(Duration::from_millis(700));
    let mut recent_events: VecDeque<SecurityEvent> = VecDeque::with_capacity(20);
    let started_at = chrono::Utc::now();
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !json_output {
                    render_watch_ui(&recent_events, started_at);
                } else {
                    debug!("watch loop heartbeat");
                }
            }
            msg = rx.recv() => {
                match msg {
                    Ok(event) => {
                        if json_output {
                            match serde_json::to_string(&event) {
                                Ok(line) => println!("{line}"),
                                Err(err) => error!(?err, "failed to serialize event"),
                            }
                        } else {
                            if recent_events.len() >= 20 {
                                let _ = recent_events.pop_back();
                            }
                            recent_events.push_front(event);
                            render_watch_ui(&recent_events, started_at);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(lagged = n, "watch subscriber lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn run_test_alerts(cfg: Config, json_output: bool) -> Result<(), DynError> {
    let (event_tx, _) = broadcast::channel::<SecurityEvent>(64);
    let alerts = AlertDispatcher::new(cfg, event_tx.subscribe())?;
    let alerts_handle = tokio::spawn(async move { alerts.run().await });

    let started_at = chrono::Utc::now();
    let mut recent_events: VecDeque<SecurityEvent> = VecDeque::with_capacity(20);

    for event in build_test_events() {
        let _ = event_tx.send(event.clone());

        if json_output {
            match serde_json::to_string(&event) {
                Ok(line) => println!("{line}"),
                Err(err) => error!(?err, "failed to serialize test event"),
            }
        } else {
            if recent_events.len() >= 20 {
                let _ = recent_events.pop_back();
            }
            recent_events.push_front(event);
            render_watch_ui(&recent_events, started_at);
        }

        sleep(Duration::from_millis(350)).await;
    }

    sleep(Duration::from_secs(2)).await;
    alerts_handle.abort();
    Ok(())
}

fn build_test_events() -> Vec<SecurityEvent> {
    let green_proc = ProcessInfo {
        pid: 4242,
        ppid: 2211,
        name: "codex".to_string(),
        cmdline: "codex --task review".to_string(),
        exe: "/usr/local/bin/codex".to_string(),
        cwd: "/home/user/project".to_string(),
        username: "user".to_string(),
        open_files: vec![],
        parent_chain: vec!["bash(2211)".to_string(), "tmux(1111)".to_string()],
    };

    let yellow_proc = ProcessInfo {
        pid: 4343,
        ppid: 4242,
        name: "bash".to_string(),
        cmdline: "bash -lc curl https://example.com/bootstrap.sh".to_string(),
        exe: "/usr/bin/bash".to_string(),
        cwd: "/home/user/project".to_string(),
        username: "user".to_string(),
        open_files: vec!["/tmp/bootstrap.sh".to_string()],
        parent_chain: vec!["codex(4242)".to_string(), "bash(2211)".to_string()],
    };

    let orange_proc = ProcessInfo {
        pid: 4444,
        ppid: 4242,
        name: "python3".to_string(),
        cmdline: "python3 -c \"import socket\"".to_string(),
        exe: "/usr/bin/python3".to_string(),
        cwd: "/home/user/project".to_string(),
        username: "user".to_string(),
        open_files: vec![],
        parent_chain: vec!["codex(4242)".to_string(), "bash(2211)".to_string()],
    };

    let red_proc = ProcessInfo {
        pid: 4545,
        ppid: 4242,
        name: "cat".to_string(),
        cmdline: "cat ~/.ssh/id_rsa".to_string(),
        exe: "/usr/bin/cat".to_string(),
        cwd: "/home/user".to_string(),
        username: "user".to_string(),
        open_files: vec!["/home/user/.ssh/id_rsa".to_string()],
        parent_chain: vec!["codex(4242)".to_string(), "bash(2211)".to_string()],
    };

    let mut green = SecurityEvent::new(
        EventType::ProcessNew,
        ThreatLevel::Green,
        "TEST EVENT: baseline monitored process detected".to_string(),
    );
    green.process = Some(green_proc);

    let mut yellow = SecurityEvent::new(
        EventType::ProcessShellSpawn,
        ThreatLevel::Yellow,
        "TEST EVENT: shell spawn under monitored AI process".to_string(),
    );
    yellow.process = Some(yellow_proc);

    let mut orange = SecurityEvent::new(
        EventType::NetworkSuspicious,
        ThreatLevel::Orange,
        "TEST EVENT: suspicious outbound network activity".to_string(),
    );
    orange.process = Some(orange_proc);
    orange.connection = Some(NetConnection {
        local_addr: "10.0.0.10".to_string(),
        local_port: 54622,
        remote_addr: "198.51.100.25".to_string(),
        remote_port: 4444,
        state: "ESTABLISHED".to_string(),
        pid: 4444,
        process_name: "python3".to_string(),
    });

    let mut red = SecurityEvent::new(
        EventType::CredentialAccess,
        ThreatLevel::Red,
        "TEST EVENT: access to sensitive credential path".to_string(),
    );
    red.process = Some(red_proc);
    red.file_event = Some(FileEvent {
        path: "/home/user/.ssh/id_rsa".to_string(),
        event_type: "read".to_string(),
        old_hash: None,
        new_hash: None,
        old_perms: None,
        new_perms: None,
    });

    vec![
        infer_and_tag(green),
        infer_and_tag(yellow),
        infer_and_tag(orange),
        infer_and_tag(red),
    ]
}

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

fn run_scan(cfg: Config, json_output: bool) -> Result<(), DynError> {
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
        let process_tree = build_scan_tree(root_pid, &process_table, &children)
            .unwrap_or_else(|| ScanProcessNode {
                pid: root_process.pid,
                name: root_process.name.clone(),
                cmdline: root_process.cmdline.clone(),
                children: Vec::new(),
            });
        let mut network_connections = collect_network_connections(&monitored, &process_table);
        let mut sensitive_open_files = collect_sensitive_open_files(&monitored, &process_table, &cfg);

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
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_scan_report(&report);
    }

    Ok(())
}

fn render_scan_report(report: &ScanReport) {
    println!(
        "{}  {}",
        Style::new().bold().paint("LEASH SCAN"),
        report.timestamp.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S")
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
                println!("    {} ({}) {}", fd.process_name, fd.pid, truncate(&fd.path, 120));
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
        let cmdline = process.cmdline().ok().map(|c| c.join(" ")).unwrap_or_default();
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

    cfg.ai_agents.iter().any(|agent| {
        let needle = agent.to_ascii_lowercase();
        name.contains(&needle) || cmdline.contains(&needle) || exe.contains(&needle)
    })
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

fn render_watch_ui(recent_events: &VecDeque<SecurityEvent>, started_at: chrono::DateTime<chrono::Utc>) {
    print!("\x1b[2J\x1b[H");
    let now = chrono::Local::now();
    let uptime = chrono::Utc::now() - started_at;
    println!(
        "{}  {}  uptime={}s",
        Style::new().bold().paint("LEASH WATCH"),
        now.format("%Y-%m-%d %H:%M:%S"),
        uptime.num_seconds()
    );
    println!("{}", "─".repeat(90));

    if recent_events.is_empty() {
        println!("No events yet. Waiting for telemetry...");
        return;
    }

    for event in recent_events.iter().take(12) {
        let level = color_for_level(event.threat_level);
        println!(
            "{} {} {}",
            level,
            Color::Cyan.paint(format!("[{}]", event.event_type)),
            event.narrative
        );
        println!("   time: {}", event.timestamp.with_timezone(&chrono::Local).format("%H:%M:%S"));
        if let Some(process) = &event.process {
            println!(
                "   proc: {} ({})  exe: {}",
                Style::new().bold().paint(process.name.clone()),
                process.pid,
                truncate(&process.exe, 50)
            );
            println!("   tree: {}", format_process_tree(process));
        }
        if let Some(file_event) = &event.file_event {
            println!("   path: {}", truncate(&file_event.path, 80));
        }
        if !event.mitre.is_empty() {
            let techniques = event
                .mitre
                .iter()
                .map(|m| format!("{} {}", m.technique_id, m.name))
                .collect::<Vec<_>>()
                .join("; ");
            println!("   mitre: {techniques}");
        }
        println!("{}", Style::new().dimmed().paint("·".repeat(90)));
    }
}

fn color_for_level(level: ThreatLevel) -> AnsiString<'static> {
    match level {
        ThreatLevel::Green => Color::Green.bold().paint("GREEN"),
        ThreatLevel::Yellow => Color::Yellow.bold().paint("YELLOW"),
        ThreatLevel::Orange => Color::Fixed(208).bold().paint("ORANGE"),
        ThreatLevel::Red => Color::Red.bold().paint("RED"),
        ThreatLevel::Nuclear => Color::Purple.bold().paint("NUCLEAR"),
    }
}

fn format_process_tree(process: &crate::models::ProcessInfo) -> String {
    if process.parent_chain.is_empty() {
        return format!("{}({})", process.name, process.pid);
    }

    let mut parts = process.parent_chain.clone();
    parts.reverse();
    parts.push(format!("{}({})", process.name, process.pid));
    parts.join(" -> ")
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!("{}...", value.chars().take(max_len.saturating_sub(3)).collect::<String>())
    }
}

fn print_startup_banner() {
    println!(
        "{}",
        Color::Cyan.bold().paint(
            r#"
 _      _____    _    ____  _   _
| |    | ____|  / \  / ___|| | | |
| |    |  _|   / _ \ \___ \| |_| |
| |___ | |___ / ___ \ ___) |  _  |
|_____||_____/_/   \_\____/|_| |_|
"#
        )
    );
}

fn ensure_single_instance() -> Result<(), DynError> {
    if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let proc_path = PathBuf::from(format!("/proc/{pid}"));
            if proc_path.exists() {
                return Err(format!("Leash already running with PID {pid}").into());
            }
        }
    }
    Ok(())
}

fn write_pid_file() -> Result<(), DynError> {
    fs::write(PID_FILE, format!("{}\n", std::process::id()))?;
    Ok(())
}

fn cleanup_pid_file() {
    if let Err(err) = fs::remove_file(PID_FILE) {
        debug!(?err, "failed to remove pid file");
    }
}

fn print_status(json_output: bool) -> Result<(), DynError> {
    let running = if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            Path::new(&format!("/proc/{pid}")).exists()
        } else {
            false
        }
    } else {
        false
    };

    if json_output {
        let value = serde_json::json!({
            "name": "Leash",
            "running": running,
            "pid_file": PID_FILE,
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if running {
        println!("{}", Color::Green.paint("Leash is running"));
    } else {
        println!("{}", Color::Red.paint("Leash is stopped"));
    }

    Ok(())
}

fn stop_agent(json_output: bool) -> Result<(), DynError> {
    let pid_str = fs::read_to_string(PID_FILE)?;
    let pid = pid_str.trim().parse::<i32>()?;
    signal::kill(Pid::from_raw(pid), Signal::SIGTERM)?;
    cleanup_pid_file();

    if json_output {
        let value = serde_json::json!({
            "stopped": true,
            "pid": pid,
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Sent SIGTERM to Leash (PID {pid})");
    }

    Ok(())
}

fn init_config(json_output: bool) -> Result<(), DynError> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
    let target = PathBuf::from(home).join(".config/leash/config.yaml");
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    let template = include_str!("../config/default.yaml");
    fs::write(&target, template)?;

    if json_output {
        let value = serde_json::json!({
            "initialized": true,
            "path": target,
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Initialized Leash config at {}", target.display());
    }

    Ok(())
}

#[allow(dead_code)]
fn _event_for_status(narrative: String) -> SecurityEvent {
    SecurityEvent::new(EventType::SelfTamper, ThreatLevel::Green, narrative)
}
