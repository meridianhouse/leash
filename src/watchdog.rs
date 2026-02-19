use crate::config::Config;
use crate::mitre;
use crate::models::{EventType, SecurityEvent, ThreatLevel};
use crate::stats;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::{debug, warn};

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
            if let Err(err) = self.tx.send(event) {
                stats::record_dropped_event();
                warn!(
                    event_type = %err.0.event_type,
                    "dropping event: broadcast channel full or closed"
                );
            }
            sleep(Duration::from_millis(self.cfg.monitor_interval_ms * 5)).await;
        }
    }
}
