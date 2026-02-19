use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, ProcessInfo, SecurityEvent, ThreatLevel};
use procfs::process::{FDTarget, Process};
use std::collections::{HashMap, HashSet};
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;

pub struct ProcessCollector {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    prev_pids: HashSet<i32>,
}

impl ProcessCollector {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            cfg,
            tx,
            prev_pids: HashSet::new(),
        }
    }

    pub async fn run(mut self) {
        loop {
            self.collect_once();
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms)).await;
        }
    }

    fn collect_once(&mut self) {
        let mut current: HashMap<i32, ProcessInfo> = HashMap::new();
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
            if let Some(info) = self.read_process(&proc) {
                current.insert(info.pid, info);
            }
        }

        let current_pids: HashSet<i32> = current.keys().copied().collect();

        for pid in current_pids.difference(&self.prev_pids) {
            if let Some(proc_info) = current.get(pid) {
                let event = self.analyze_new_process(proc_info.clone(), &current);
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

    fn analyze_new_process(
        &self,
        mut proc: ProcessInfo,
        all: &HashMap<i32, ProcessInfo>,
    ) -> SecurityEvent {
        proc.parent_chain = self.build_parent_chain(proc.ppid, all);
        let lower_name = proc.name.to_lowercase();
        let parent_name = all
            .get(&proc.ppid)
            .map(|p| p.name.to_lowercase())
            .unwrap_or_else(|| "unknown".into());

        let shell_binaries = ["bash", "sh", "zsh", "dash", "fish"];
        if shell_binaries.contains(&lower_name.as_str()) {
            let normal_parents = [
                "sshd", "login", "systemd", "tmux", "screen", "bash", "zsh", "sh", "node", "npm",
                "codex", "claude",
            ];
            if !normal_parents.contains(&parent_name.as_str()) {
                let mut event = SecurityEvent::new(
                    EventType::ProcessShellSpawn,
                    ThreatLevel::Yellow,
                    format!(
                        "Shell '{}' spawned by unusual parent '{}'; cmd='{}'",
                        proc.name, parent_name, proc.cmdline
                    ),
                );
                event.process = Some(proc);
                return mitre::tag_event(event, "T1059.004");
            }
        }

        let sensitive = proc.open_files.iter().any(|f| {
            self.cfg
                .sensitive_path_keywords
                .iter()
                .any(|k| f.contains(k))
        });
        if sensitive {
            let is_ai = self
                .cfg
                .ai_agents
                .iter()
                .any(|agent| lower_name.contains(&agent.to_lowercase()));
            let legit_parent = self
                .cfg
                .legitimate_ai_parents
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&parent_name));

            let level = if is_ai && !legit_parent {
                ThreatLevel::Red
            } else {
                ThreatLevel::Orange
            };

            let mut event = SecurityEvent::new(
                EventType::CredentialAccess,
                level,
                format!(
                    "Process '{}' accessed sensitive files (parent='{}')",
                    proc.name, parent_name
                ),
            );
            event.process = Some(proc);
            return mitre::tag_event(event, "T1552.001");
        }

        let mut event = SecurityEvent::new(
            EventType::ProcessNew,
            ThreatLevel::Green,
            format!("New process '{}' (PID {})", proc.name, proc.pid),
        );
        event.process = Some(proc);
        mitre::infer_and_tag(event)
    }

    fn build_parent_chain(&self, start_ppid: i32, all: &HashMap<i32, ProcessInfo>) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = start_ppid;

        for _ in 0..6 {
            if current <= 1 {
                break;
            }
            let Some(parent) = all.get(&current) else {
                break;
            };
            chain.push(format!("{}({})", parent.name, parent.pid));
            current = parent.ppid;
        }

        chain
    }

    fn read_process(&self, proc: &Process) -> Option<ProcessInfo> {
        let stat = proc.stat().ok()?;
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
        let open_files = self.read_open_files(proc);

        Some(ProcessInfo {
            pid: stat.pid,
            ppid: stat.ppid,
            name: stat.comm,
            cmdline,
            exe,
            cwd,
            username: String::new(),
            open_files,
            parent_chain: Vec::new(),
        })
    }

    fn read_open_files(&self, proc: &Process) -> Vec<String> {
        let mut files = Vec::new();
        let fds = match proc.fd() {
            Ok(fds) => fds,
            Err(_) => return files,
        };

        for fd in fds.flatten() {
            if let FDTarget::Path(p) = fd.target {
                files.push(p.display().to_string());
            }
        }

        files
    }
}
