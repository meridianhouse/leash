use crate::config::Config;
use crate::models::{SecurityEvent, ThreatLevel};
use reqwest::Client;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tokio::sync::broadcast;
use tracing::{error, warn};

pub struct AlertDispatcher {
    cfg: Config,
    rx: broadcast::Receiver<SecurityEvent>,
    client: Client,
    min_level: ThreatLevel,
}

impl AlertDispatcher {
    pub fn new(
        cfg: Config,
        rx: broadcast::Receiver<SecurityEvent>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            min_level: parse_level(&cfg.alerts.min_level),
            cfg,
            rx,
            client: Client::builder().build()?,
        })
    }

    pub async fn run(mut self) {
        loop {
            let event = match self.rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            if event.threat_level < self.min_level {
                continue;
            }

            if let Err(err) = self.write_local_log(&event) {
                error!(?err, "failed to write alert log");
            }

            for url in &self.cfg.webhook_urls {
                if let Err(err) = self.send_webhook(url, &event).await {
                    warn!(?err, webhook = url, "webhook delivery failed");
                }
            }
        }
    }

    fn write_local_log(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = Path::new(&self.cfg.alert_log_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{}", serde_json::to_string(event)?)?;
        Ok(())
    }

    async fn send_webhook(
        &self,
        url: &str,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let message = format!(
            "[{:?}] {}: {}",
            event.threat_level, event.event_type, event.narrative
        );

        let payload = if url.contains("discord.com") {
            json!({ "content": message })
        } else {
            json!({ "text": message })
        };

        self.client
            .post(url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
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
