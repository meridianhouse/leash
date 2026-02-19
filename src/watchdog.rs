use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, SecurityEvent, ThreatLevel};
use crate::stats;
use std::fs;
use std::path::{Path, PathBuf};
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
    service_path: Option<PathBuf>,
    service_hash: Option<String>,
    service_restart: Option<String>,
}

impl Watchdog {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        let exe_path = "/proc/self/exe".to_string();
        let baseline_hash = compute_file_blake3(&exe_path);
        if let Some(hash) = baseline_hash.as_deref()
            && let Err(err) = persist_integrity_hash(hash)
        {
            warn!(?err, "failed to persist binary integrity baseline");
        }
        let config_path = default_config_path();
        let config_hash = compute_file_blake3(&config_path);
        let service_path = find_service_file();
        let (service_hash, service_restart) = service_path
            .as_deref()
            .and_then(read_service_state)
            .map(|state| (Some(state.hash), state.restart))
            .unwrap_or((None, None));
        Self {
            cfg,
            tx,
            exe_path,
            config_path,
            baseline_hash,
            config_hash,
            service_path,
            service_hash,
            service_restart,
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
            if let Some(path) = self.service_path.as_deref() {
                check_service_file(path, &mut self.service_hash, &self.tx);
                check_service_restart(path, &mut self.service_restart, &self.tx);
            } else {
                self.service_path = find_service_file();
                if let Some(path) = self.service_path.as_deref()
                    && let Some(state) = read_service_state(path)
                {
                    self.service_hash = Some(state.hash);
                    self.service_restart = state.restart;
                }
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
        let current_hash = compute_file_blake3(&self.exe_path)?;
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
        let current_hash = compute_file_blake3(&self.config_path);
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

fn compute_file_blake3(path: impl AsRef<std::path::Path>) -> Option<String> {
    let path = path.as_ref();
    let contents = fs::read(path).ok()?;
    Some(blake3::hash(&contents).to_hex().to_string())
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
    Ok(PathBuf::from(home).join(".local/state/leash/integrity.blake3"))
}

fn default_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return PathBuf::from("/etc/leash/config.yaml");
    }
    PathBuf::from(home).join(".config/leash/config.yaml")
}

fn find_service_file() -> Option<PathBuf> {
    let candidates = [
        std::env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".config/systemd/user/leash.service")),
        Some(PathBuf::from("/etc/systemd/system/leash.service")),
    ];

    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn check_service_file(
    path: &Path,
    stored_hash: &mut Option<String>,
    tx: &broadcast::Sender<SecurityEvent>,
) {
    let Some(contents) = fs::read(path).ok() else {
        return;
    };
    let current_hash = blake3::hash(&contents).to_hex().to_string();
    if stored_hash.as_deref() == Some(current_hash.as_str()) {
        return;
    }
    *stored_hash = Some(current_hash);
    send_self_tamper_alert(
        tx,
        ThreatLevel::Red,
        format!("systemd service file changed: {}", path.display()),
    );
}

fn check_service_restart(
    path: &Path,
    stored_restart: &mut Option<String>,
    tx: &broadcast::Sender<SecurityEvent>,
) {
    let Some(contents) = fs::read_to_string(path).ok() else {
        return;
    };
    let current_restart = parse_restart_value(&contents);
    if *stored_restart == current_restart {
        return;
    }
    *stored_restart = current_restart.clone();
    send_self_tamper_alert(
        tx,
        ThreatLevel::Red,
        format!(
            "systemd Restart= changed to '{}' in {}",
            current_restart.as_deref().unwrap_or("<unset>"),
            path.display()
        ),
    );
}

fn send_self_tamper_alert(
    tx: &broadcast::Sender<SecurityEvent>,
    level: ThreatLevel,
    narrative: String,
) {
    let event = mitre::infer_and_tag(SecurityEvent::new(EventType::SelfTamper, level, narrative));
    if let Err(err) = tx.send(event) {
        stats::record_dropped_event();
        warn!(
            event_type = %err.0.event_type,
            "dropping event: broadcast channel full or closed"
        );
    }
}

fn parse_restart_value(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            return None;
        }
        trimmed
            .strip_prefix("Restart=")
            .map(|value| value.trim().to_string())
    })
}

struct ServiceState {
    hash: String,
    restart: Option<String>,
}

fn read_service_state(path: &Path) -> Option<ServiceState> {
    let contents = fs::read(path).ok()?;
    let hash = blake3::hash(&contents).to_hex().to_string();
    let restart = parse_restart_value(std::str::from_utf8(&contents).ok()?);
    Some(ServiceState { hash, restart })
}
