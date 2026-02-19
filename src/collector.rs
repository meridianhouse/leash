use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, ProcessEnrichment, ProcessInfo, SecurityEvent, ThreatLevel};
use procfs::process::Process;
use std::collections::{HashMap, HashSet};
use std::fs;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;

#[derive(Clone)]
struct ProcessSnapshot {
    info: ProcessInfo,
    enrichment: ProcessEnrichment,
    is_ai_agent: bool,
}

pub struct ProcessCollector {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    prev_pids: HashSet<i32>,
    process_tree: HashMap<i32, Vec<i32>>,
}

impl ProcessCollector {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            cfg,
            tx,
            prev_pids: HashSet::new(),
            process_tree: HashMap::new(),
        }
    }

    pub async fn run(mut self) {
        loop {
            self.collect_once();
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms)).await;
        }
    }

    fn collect_once(&mut self) {
        let mut current: HashMap<i32, ProcessSnapshot> = HashMap::new();
        let all = match procfs::process::all_processes() {
            Ok(p) => p,
            Err(err) => {
                warn!(?err, "unable to enumerate /proc");
                return;
            }
        };

        for proc_result in all {
            let proc = match proc_result {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Some(snapshot) = self.read_process(&proc) {
                current.insert(snapshot.info.pid, snapshot);
            }
        }

        let current_pids: HashSet<i32> = current.keys().copied().collect();
        self.process_tree = self.build_process_tree(&current);
        let (ai_roots, monitored) = self.compute_monitored_sets(&current, &self.process_tree);

        for pid in current_pids.difference(&self.prev_pids) {
            let Some(snapshot) = current.get(pid) else {
                continue;
            };

            if !monitored.contains(pid) {
                continue;
            }

            for event in self.analyze_monitored_process(*pid, snapshot, &current, &ai_roots) {
                let _ = self.tx.send(event);
            }
        }

        for pid in self.prev_pids.difference(&current_pids) {
            let event = mitre::infer_and_tag(SecurityEvent::new(
                EventType::ProcessExit,
                ThreatLevel::Green,
                format!("Process exited: PID {pid}"),
            ));
            let _ = self.tx.send(event);
        }

        self.prev_pids = current_pids;
    }

    fn analyze_monitored_process(
        &self,
        pid: i32,
        snapshot: &ProcessSnapshot,
        all: &HashMap<i32, ProcessSnapshot>,
        ai_roots: &HashSet<i32>,
    ) -> Vec<SecurityEvent> {
        let mut events = Vec::new();

        let ancestry = self.build_ancestry_chain(pid, all, ai_roots);
        let ancestry_names: Vec<String> = ancestry.iter().map(|(_, name)| name.clone()).collect();
        let ancestry_text = ancestry_names.join(" -> ");
        let is_descendant = ancestry.len() > 1;
        let process_level = if snapshot.is_ai_agent {
            ThreatLevel::Orange
        } else {
            ThreatLevel::Green
        };
        let process_label = if snapshot.is_ai_agent {
            "AI agent process detected"
        } else {
            "Monitored process observed"
        };

        events.push(self.make_event(
            EventType::ProcessNew,
            process_level,
            format!(
                "{process_label}: {} (pid={}) | ancestry: {}",
                snapshot.info.name, snapshot.info.pid, ancestry_text
            ),
            snapshot,
            all,
        ));

        let lower_name = snapshot.info.name.to_ascii_lowercase();
        if is_descendant && ["bash", "sh", "zsh"].contains(&lower_name.as_str()) {
            events.push(self.make_event(
                EventType::ProcessShellSpawn,
                ThreatLevel::Yellow,
                format!("Monitored shell spawn detected: {ancestry_text}"),
                snapshot,
                all,
            ));
        }

        let credential_hits = detect_credential_paths(&snapshot.enrichment.open_fds);
        if !credential_hits.is_empty() {
            events.push(self.make_event(
                EventType::CredentialAccess,
                ThreatLevel::Red,
                format!(
                    "Monitored process accessed credential material: {ancestry_text} | files={}",
                    credential_hits.join(", ")
                ),
                snapshot,
                all,
            ));
        }

        let dangerous_hits =
            detect_dangerous_commands(&snapshot.info.cmdline, &snapshot.enrichment.working_dir);
        if !dangerous_hits.is_empty() {
            let level = if dangerous_hits.iter().any(|hit| {
                hit.contains("write_sensitive_path")
                    || hit.contains("download_exec")
                    || hit.contains("encoded_python")
            }) {
                ThreatLevel::Red
            } else {
                ThreatLevel::Orange
            };
            let url = extract_url(&snapshot.info.cmdline).unwrap_or_default();
            let chain = if url.is_empty() {
                ancestry_text.clone()
            } else {
                format!("{ancestry_text} -> {url}")
            };
            events.push(self.make_event(
                EventType::NetworkSuspicious,
                level,
                format!(
                    "Dangerous command pattern(s) [{}] | ancestry: {chain}",
                    dangerous_hits.join(",")
                ),
                snapshot,
                all,
            ));
        }

        events
    }

    fn make_event(
        &self,
        event_type: EventType,
        threat_level: ThreatLevel,
        narrative: String,
        snapshot: &ProcessSnapshot,
        all: &HashMap<i32, ProcessSnapshot>,
    ) -> SecurityEvent {
        let mut proc = snapshot.info.clone();
        proc.parent_chain = self.build_parent_chain(proc.ppid, all);

        let mut event = SecurityEvent::new(event_type, threat_level, narrative);
        event.process = Some(proc);
        event.enrichment = Some(snapshot.enrichment.clone());
        mitre::infer_and_tag(event)
    }

    fn build_process_tree(&self, all: &HashMap<i32, ProcessSnapshot>) -> HashMap<i32, Vec<i32>> {
        let mut tree: HashMap<i32, Vec<i32>> = HashMap::new();
        for (pid, snapshot) in all {
            tree.entry(snapshot.info.ppid).or_default().push(*pid);
        }
        tree
    }

    fn compute_monitored_sets(
        &self,
        all: &HashMap<i32, ProcessSnapshot>,
        tree: &HashMap<i32, Vec<i32>>,
    ) -> (HashSet<i32>, HashSet<i32>) {
        let mut roots = HashSet::new();
        let mut monitored = HashSet::new();

        for (pid, snapshot) in all {
            if snapshot.is_ai_agent {
                roots.insert(*pid);
                let mut stack = vec![*pid];
                while let Some(current) = stack.pop() {
                    if !monitored.insert(current) {
                        continue;
                    }
                    if let Some(children) = tree.get(&current) {
                        for child in children {
                            stack.push(*child);
                        }
                    }
                }
            }
        }

        (roots, monitored)
    }

    fn build_ancestry_chain(
        &self,
        pid: i32,
        all: &HashMap<i32, ProcessSnapshot>,
        ai_roots: &HashSet<i32>,
    ) -> Vec<(i32, String)> {
        let mut chain = Vec::new();
        let mut current = pid;

        for _ in 0..64 {
            let Some(proc) = all.get(&current) else {
                break;
            };
            chain.push((proc.info.pid, proc.info.name.clone()));
            if ai_roots.contains(&current) || current <= 1 {
                break;
            }
            current = proc.info.ppid;
        }

        chain.reverse();
        chain
    }

    fn build_parent_chain(
        &self,
        start_ppid: i32,
        all: &HashMap<i32, ProcessSnapshot>,
    ) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = start_ppid;

        for _ in 0..16 {
            if current <= 1 {
                break;
            }
            let Some(parent) = all.get(&current) else {
                break;
            };
            chain.push(format!("{}({})", parent.info.name, parent.info.pid));
            current = parent.info.ppid;
        }

        chain
    }

    fn read_process(&self, proc: &Process) -> Option<ProcessSnapshot> {
        let stat = proc.stat().ok()?;
        let pid = stat.pid;
        let cmdline = proc.cmdline().ok().map(|v| v.join(" ")).unwrap_or_default();
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
        let open_fds = self.read_open_fds(pid);
        let env = self.read_env_of_interest(pid);
        let (memory_rss_kb, memory_vmsize_kb, username) = self.read_status_fields(pid);
        let is_ai_agent = self.is_ai_agent(&stat.comm, &cmdline, &exe);

        let info = ProcessInfo {
            pid,
            ppid: stat.ppid,
            name: stat.comm,
            cmdline: cmdline.clone(),
            exe,
            cwd: cwd.clone(),
            username,
            open_files: open_fds.clone(),
            parent_chain: Vec::new(),
        };

        let enrichment = ProcessEnrichment {
            full_cmdline: cmdline,
            working_dir: cwd,
            env,
            open_fds,
            memory_rss_kb,
            memory_vmsize_kb,
        };

        Some(ProcessSnapshot {
            info,
            enrichment,
            is_ai_agent,
        })
    }

    fn is_ai_agent(&self, name: &str, cmdline: &str, exe: &str) -> bool {
        let name = name.to_ascii_lowercase();
        let cmdline = cmdline.to_ascii_lowercase();
        let exe = exe.to_ascii_lowercase();
        let configured_match = self.cfg.ai_agents.iter().any(|agent| {
            let needle = agent.to_ascii_lowercase();
            name.contains(&needle) || cmdline.contains(&needle) || exe.contains(&needle)
        });
        if configured_match {
            return true;
        }

        let cmdline_needles = ["anthropic", "claude-code", "cursor.sh", "opencode"];
        cmdline_needles
            .iter()
            .any(|needle| cmdline.contains(needle) || exe.contains(needle))
    }

    fn read_open_fds(&self, pid: i32) -> Vec<String> {
        let mut fds = Vec::new();
        let fd_dir = format!("/proc/{pid}/fd");
        let entries = match fs::read_dir(fd_dir) {
            Ok(entries) => entries,
            Err(_) => return fds,
        };

        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                fds.push(target.display().to_string());
            }
        }

        fds
    }

    fn read_env_of_interest(&self, pid: i32) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let env_path = format!("/proc/{pid}/environ");
        let bytes = match fs::read(env_path) {
            Ok(data) => data,
            Err(_) => return out,
        };

        for item in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let entry = String::from_utf8_lossy(item);
            let mut parts = entry.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            if matches!(key, "PATH" | "HOME" | "USER") {
                out.insert(key.to_string(), value.to_string());
            }
        }

        out
    }

    fn read_status_fields(&self, pid: i32) -> (Option<u64>, Option<u64>, String) {
        let status_path = format!("/proc/{pid}/status");
        let status = match fs::read_to_string(status_path) {
            Ok(raw) => raw,
            Err(_) => return (None, None, String::new()),
        };

        let mut vmrss = None;
        let mut vmsize = None;
        let mut username = String::new();

        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                vmrss = parse_status_kb(rest);
            } else if let Some(rest) = line.strip_prefix("VmSize:") {
                vmsize = parse_status_kb(rest);
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                username = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
            }
        }

        (vmrss, vmsize, username)
    }
}

fn parse_status_kb(raw: &str) -> Option<u64> {
    raw.split_whitespace().next()?.parse::<u64>().ok()
}

fn extract_url(cmdline: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .find(|part| part.starts_with("http://") || part.starts_with("https://"))
        .map(ToString::to_string)
}

fn detect_credential_paths(open_fds: &[String]) -> Vec<String> {
    const TARGETS: &[&str] = &[
        "/.ssh/id_rsa",
        "/.ssh/id_ed25519",
        "/.ssh/known_hosts",
        "/.aws/credentials",
        "/.aws/config",
        "/.gitconfig",
        "/.npmrc",
        "/.netrc",
    ];

    open_fds
        .iter()
        .filter_map(|fd| {
            let normalized = fd.to_ascii_lowercase();
            TARGETS
                .iter()
                .find(|needle| normalized.ends_with(**needle))
                .map(|_| fd.clone())
        })
        .take(6)
        .collect()
}

fn detect_dangerous_commands(cmdline: &str, working_dir: &str) -> Vec<&'static str> {
    let lower = cmdline.to_ascii_lowercase();
    let mut hits = Vec::new();

    if (lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("fetch ")
        || lower.contains("http://")
        || lower.contains("https://"))
        && (lower.contains("| bash")
            || lower.contains("| sh")
            || lower.contains("| /bin/bash")
            || lower.contains("| /bin/sh"))
    {
        hits.push("download_pipe_shell");
    }

    if lower.contains("wget ")
        && (lower.contains("-o - | sh")
            || lower.contains("-o -|sh")
            || lower.contains("-o- | sh")
            || lower.contains("-o- |sh"))
    {
        hits.push("wget_pipe_shell");
    }

    if lower.contains("base64 -d") || lower.contains("base64 --decode") {
        hits.push("base64_decode");
    }

    if (lower.contains("python -c") || lower.contains("python3 -c")) && lower.contains("base64") {
        hits.push("encoded_python");
    }

    if lower.contains(" eval ") || lower.starts_with("eval ") {
        hits.push("eval_execution");
    }

    if let Some(host) = extract_ssh_target_host(&lower) {
        if is_unusual_ssh_host(&host) {
            hits.push("ssh_unusual_host");
        }
    }

    if (lower.starts_with("nc ") || lower.contains(" nc ") || lower.starts_with("ncat "))
        && lower.contains(" -l")
    {
        hits.push("netcat_listener");
    }

    if lower.contains("chmod +x")
        && (lower.contains("http://")
            || lower.contains("https://")
            || lower.contains("curl ")
            || lower.contains("wget ")
            || lower.contains("/tmp/")
            || working_dir.starts_with("/tmp"))
    {
        hits.push("download_exec");
    }

    if (lower.contains("touch ") || lower.contains("mkdir ")) && references_sensitive_paths(&lower)
    {
        hits.push("touch_mkdir_sensitive");
    }

    if references_sensitive_paths(&lower)
        && (lower.contains(" > /etc")
            || lower.contains(" >> /etc")
            || lower.contains("tee /etc")
            || lower.contains("cp ")
            || lower.contains("mv ")
            || lower.contains("install "))
    {
        hits.push("write_sensitive_path");
    }

    hits
}

fn extract_ssh_target_host(cmdline: &str) -> Option<String> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();
    if tokens.first().copied() != Some("ssh") {
        return None;
    }

    let mut idx = 1;
    while idx < tokens.len() {
        let tok = tokens[idx];
        if tok == "-p" || tok == "-i" || tok == "-l" || tok == "-o" || tok == "-f" || tok == "-n" {
            idx += 2;
            continue;
        }
        if tok.starts_with('-') {
            idx += 1;
            continue;
        }

        let host = tok
            .split('@')
            .next_back()
            .unwrap_or_default()
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        return (!host.is_empty()).then_some(host);
    }

    None
}

fn is_unusual_ssh_host(host: &str) -> bool {
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return false;
    }
    if host.ends_with(".local") || host.ends_with(".lan") || host.ends_with(".internal") {
        return false;
    }

    if let Some((a, b, _, _)) = parse_ipv4_octets(host) {
        if a == 10 {
            return false;
        }
        if a == 172 && (16..=31).contains(&b) {
            return false;
        }
        if a == 192 && b == 168 {
            return false;
        }
    }

    true
}

fn references_sensitive_paths(text: &str) -> bool {
    text.contains("/etc/") || text.contains("/usr/bin/") || text.contains("/bin/")
}

fn parse_ipv4_octets(host: &str) -> Option<(u8, u8, u8, u8)> {
    let mut parts = host.split('.');
    let a = parts.next()?.parse::<u8>().ok()?;
    let b = parts.next()?.parse::<u8>().ok()?;
    let c = parts.next()?.parse::<u8>().ok()?;
    let d = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c, d))
}
