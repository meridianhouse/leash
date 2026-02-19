use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, SecurityEvent, ThreatLevel};
use crate::stats;
use std::fs;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::{debug, warn};

pub struct Watchdog {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
    exe_path: Option<String>,
    baseline_hash: Option<String>,
}

impl Watchdog {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        let exe_path = std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string());
        let baseline_hash = exe_path.as_deref().and_then(compute_file_hash);
        Self {
            cfg,
            tx,
            exe_path,
            baseline_hash,
        }
    }

    pub async fn run(mut self) {
        loop {
            debug!("watchdog heartbeat");
            if let Some(alert) = self.check_binary_tamper() {
                self.send_event(alert);
            }
            let event = mitre::infer_and_tag(SecurityEvent::new(
                EventType::SelfTamper,
                ThreatLevel::Green,
                "Watchdog heartbeat".to_string(),
            ));
            self.send_event(event);
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms * 5)).await;
        }
    }

    fn check_binary_tamper(&mut self) -> Option<SecurityEvent> {
        let path = self.exe_path.as_deref()?;
        let current_hash = compute_file_hash(path)?;
        let baseline = self.baseline_hash.clone()?;
        if current_hash == baseline {
            return None;
        }

        let event = mitre::infer_and_tag(SecurityEvent::new(
            EventType::SelfTamper,
            ThreatLevel::Red,
            format!("Leash binary hash changed while running: {path}"),
        ));
        self.baseline_hash = Some(current_hash);
        Some(event)
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

fn compute_file_hash(path: &str) -> Option<String> {
    let data = fs::read(path).ok()?;
    Some(blake3::hash(&data).to_hex().to_string())
}
