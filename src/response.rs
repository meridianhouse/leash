use crate::config::Config;
use crate::models::{ProcessInfo, SecurityEvent, ThreatLevel};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::fs;
use tokio::sync::broadcast;
use tracing::{info, warn};

pub struct ResponseEngine {
    cfg: Config,
    rx: broadcast::Receiver<SecurityEvent>,
}

impl ResponseEngine {
    pub fn new(cfg: Config, rx: broadcast::Receiver<SecurityEvent>) -> Self {
        Self { cfg, rx }
    }

    pub async fn run(mut self) {
        loop {
            let event = match self.rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            self.respond(event);
        }
    }

    fn respond(&self, event: SecurityEvent) {
        if !self.cfg.response.enable_sigstop {
            return;
        }

        let min = parse_level(&self.cfg.response.stop_min_level);
        if event.threat_level < min {
            return;
        }

        let proc = match event.process {
            Some(p) => p,
            None => return,
        };

        if self
            .cfg
            .protected_processes
            .iter()
            .any(|name| proc.name.eq_ignore_ascii_case(name))
        {
            warn!(
                pid = proc.pid,
                process = proc.name,
                "skip SIGSTOP for protected process"
            );
            return;
        }

        if !process_identity_matches(&proc) {
            warn!(
                pid = proc.pid,
                process = proc.name,
                "skip SIGSTOP because process identity changed (possible PID reuse)"
            );
            return;
        }

        match kill(Pid::from_raw(proc.pid), Signal::SIGSTOP) {
            Ok(_) => info!(pid = proc.pid, process = proc.name, "SIGSTOP applied"),
            Err(err) => warn!(?err, pid = proc.pid, process = proc.name, "SIGSTOP failed"),
        }
    }
}

fn process_identity_matches(proc: &ProcessInfo) -> bool {
    let exe_path = format!("/proc/{}/exe", proc.pid);
    let current_exe = match fs::read_link(exe_path) {
        Ok(path) => path.display().to_string(),
        Err(_) => return false,
    };

    if !proc.exe.is_empty() && current_exe != proc.exe {
        return false;
    }

    true
}

fn parse_level(raw: &str) -> ThreatLevel {
    match raw.to_ascii_lowercase().as_str() {
        "yellow" => ThreatLevel::Yellow,
        "orange" => ThreatLevel::Orange,
        "red" => ThreatLevel::Red,
        "nuclear" => ThreatLevel::Nuclear,
        _ => ThreatLevel::Green,
    }
}
