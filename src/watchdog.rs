use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, SecurityEvent, ThreatLevel};
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::debug;

pub struct Watchdog {
    cfg: Config,
    tx: broadcast::Sender<SecurityEvent>,
}

impl Watchdog {
    pub fn new(cfg: Config, tx: broadcast::Sender<SecurityEvent>) -> Self {
        Self { cfg, tx }
    }

    pub async fn run(self) {
        loop {
            debug!("watchdog heartbeat");
            let event = mitre::infer_and_tag(SecurityEvent::new(
                EventType::SelfTamper,
                ThreatLevel::Green,
                "Watchdog heartbeat".to_string(),
            ));
            let _ = self.tx.send(event);
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms * 5)).await;
        }
    }
}
