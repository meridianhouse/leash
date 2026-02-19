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

        events.push(self.make_event(
            EventType::ProcessNew,
            ThreatLevel::Green,
            format!(
                "Monitored process observed: {} (pid={}) | ancestry: {}",
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

        if is_descendant {
            let sensitive_hits: Vec<String> = snapshot
                .enrichment
                .open_fds
                .iter()
                .filter(|fd| {
                    self.cfg
                        .sensitive_path_keywords
                        .iter()
                        .any(|k| fd.to_ascii_lowercase().contains(&k.to_ascii_lowercase()))
                })
                .take(4)
                .cloned()
                .collect();

            if !sensitive_hits.is_empty() {
                events.push(self.make_event(
                    EventType::CredentialAccess,
                    ThreatLevel::Red,
                    format!(
                        "Monitored child accessed sensitive paths: {ancestry_text} | fds={} ",
                        sensitive_hits.join(", ")
                    ),
                    snapshot,
                    all,
                ));
            }
        }

        if is_descendant {
            let lower_cmd = snapshot.info.cmdline.to_ascii_lowercase();
            let suspicious = [
                "curl ",
                "wget ",
                " nc ",
                "ncat ",
                "base64",
                "python -c",
                " eval ",
            ];
            let matched: Vec<&str> = suspicious
                .iter()
                .copied()
                .filter(|needle| lower_cmd.contains(needle))
                .collect();

            if !matched.is_empty() || lower_cmd.starts_with("nc ") || lower_cmd.starts_with("ncat ")
            {
                let mut matched = matched;
                if lower_cmd.starts_with("nc ") {
                    matched.push("nc ");
                }
                if lower_cmd.starts_with("ncat ") {
                    matched.push("ncat ");
                }
                let url = extract_url(&snapshot.info.cmdline).unwrap_or_default();
                let chain = if url.is_empty() {
                    ancestry_text.clone()
                } else {
                    format!("{ancestry_text} -> {url}")
                };
                events.push(self.make_event(
                    EventType::NetworkSuspicious,
                    ThreatLevel::Orange,
                    format!(
                        "Monitored suspicious command(s) [{}] | ancestry: {chain}",
                        matched.join(",")
                    ),
                    snapshot,
                    all,
                ));
            }
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
        self.cfg.ai_agents.iter().any(|agent| {
            let needle = agent.to_ascii_lowercase();
            name.contains(&needle) || cmdline.contains(&needle) || exe.contains(&needle)
        })
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
                username = rest.split_whitespace().next().unwrap_or_default().to_string();
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
