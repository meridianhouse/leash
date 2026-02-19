use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, SecurityEvent, ThreatLevel};
use crate::stats;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::{debug, warn};

pub struct Watchdog {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    exe_path: String,
    config_path: PathBuf,
    baseline_hash: Option<String>,
    config_hash: Option<String>,
}

impl Watchdog {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        let exe_path = "/proc/self/exe".to_string();
        let baseline_hash = compute_file_sha256(&exe_path);
        if let Some(hash) = baseline_hash.as_deref()
            && let Err(err) = persist_integrity_hash(hash)
        {
            warn!(?err, "failed to persist binary integrity baseline");
        }
        let config_path = default_config_path();
        let config_hash = compute_file_sha256(&config_path);
        Self {
            cfg,
            tx,
            exe_path,
            config_path,
            baseline_hash,
            config_hash,
        }
    }

    pub async fn run(mut self) {
        loop {
            debug!("watchdog heartbeat");
            if let Some(alert) = self.check_binary_tamper() {
                self.send_event(alert);
            }
            if let Some(alert) = self.check_config_tamper() {
                self.send_event(alert);
            }
            let event = mitre::infer_and_tag(SecurityEvent::new(
                EventType::SelfTamper,
                ThreatLevel::Green,
                "Watchdog heartbeat".to_string(),
            ));
            self.send_event(event);
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms)).await;
        }
    }

    fn check_binary_tamper(&mut self) -> Option<SecurityEvent> {
        let current_hash = compute_file_sha256(&self.exe_path)?;
        let baseline = self.baseline_hash.clone()?;
        if current_hash == baseline {
            return None;
        }

        let event = mitre::infer_and_tag(SecurityEvent::new(
            EventType::SelfTamper,
            ThreatLevel::Red,
            "Leash binary modified while running".to_string(),
        ));
        if let Err(err) = persist_integrity_hash(&current_hash) {
            warn!(?err, "failed to update binary integrity baseline");
        }
        self.baseline_hash = Some(current_hash);
        Some(event)
    }

    fn check_config_tamper(&mut self) -> Option<SecurityEvent> {
        let current_hash = compute_file_sha256(&self.config_path);
        if current_hash == self.config_hash {
            return None;
        }
        self.config_hash = current_hash;
        Some(mitre::infer_and_tag(SecurityEvent::new(
            EventType::SelfTamper,
            ThreatLevel::Orange,
            "Leash configuration modified".to_string(),
        )))
    }

    fn send_event(&self, event: SecurityEvent) {
        if let Err(err) = self.tx.send(event) {
            stats::record_dropped_event();
            warn!(
                event_type = %err.0.event_type,
                "dropping event: broadcast channel full or closed"
            );
        }
    }
}

fn compute_file_sha256(path: impl AsRef<std::path::Path>) -> Option<String> {
    let path = path.as_ref();
    run_digest_command("sha256sum", &[path])
        .or_else(|| run_shasum_command(path))
        .map(|digest| digest.to_ascii_lowercase())
}

fn persist_integrity_hash(hash: &str) -> std::io::Result<()> {
    let path = integrity_hash_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{hash}\n"))
}

fn integrity_hash_path() -> std::io::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/state/leash/integrity.sha256"))
}

fn default_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return PathBuf::from("/etc/leash/config.yaml");
    }
    PathBuf::from(home).join(".config/leash/config.yaml")
}

fn run_digest_command(cmd: &str, args: &[&std::path::Path]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .split_whitespace()
        .next()
        .map(std::string::ToString::to_string)
}

fn run_shasum_command(path: &std::path::Path) -> Option<String> {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .split_whitespace()
        .next()
        .map(std::string::ToString::to_string)
}
