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

            if self.cfg.alerts.json_log.enabled {
                if let Err(err) = self.write_local_log(&event) {
                    error!(?err, "failed to write alert log");
                }
            }

            if self.cfg.alerts.slack.enabled && !self.cfg.alerts.slack.webhook_url.is_empty() {
                if let Err(err) = self.send_slack(&self.cfg.alerts.slack.webhook_url, &event).await
                {
                    warn!(?err, "slack delivery failed");
                }
            }

            if self.cfg.alerts.discord.enabled && !self.cfg.alerts.discord.webhook_url.is_empty() {
                if let Err(err) = self
                    .send_discord(&self.cfg.alerts.discord.webhook_url, &event)
                    .await
                {
                    warn!(?err, "discord delivery failed");
                }
            }

            if self.cfg.alerts.telegram.enabled
                && !self.cfg.alerts.telegram.bot_token.is_empty()
                && !self.cfg.alerts.telegram.chat_id.is_empty()
            {
                if let Err(err) = self.send_telegram(&event).await {
                    warn!(?err, "telegram delivery failed");
                }
            }
        }
    }

    fn write_local_log(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = Path::new(&self.cfg.alerts.json_log.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{}", serde_json::to_string(event)?)?;
        Ok(())
    }

    async fn send_slack(
        &self,
        url: &str,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fields = shared_fields(event);
        let mut blocks = vec![
            json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*Leash Alert* {}\n{}", severity_badge(event.threat_level), event.narrative)
                }
            }),
            json!({ "type": "divider" }),
            json!({
                "type": "section",
                "fields": fields.iter().map(|(title, value)| {
                    json!({
                        "type": "mrkdwn",
                        "text": format!("*{}*\n{}", title, value)
                    })
                }).collect::<Vec<_>>()
            }),
        ];

        if event.process.is_some() {
            blocks.push(json!({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Acknowledge" },
                        "action_id": "leash_ack",
                        "value": "ack"
                    },
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Investigate" },
                        "action_id": "leash_investigate",
                        "value": "investigate"
                    }
                ]
            }));
        }

        let payload = json!({
            "text": format!("[{}] {}", level_label(event.threat_level), event.narrative),
            "attachments": [{
                "color": slack_color(event.threat_level),
                "blocks": blocks
            }]
        });

        self.client
            .post(url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn send_discord(
        &self,
        url: &str,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload = json!({
            "embeds": [{
                "title": format!("Leash Alert {}", severity_badge(event.threat_level)),
                "description": event.narrative,
                "color": discord_color(event.threat_level),
                "fields": shared_fields(event).into_iter().map(|(name, value)| {
                    json!({
                        "name": name,
                        "value": value,
                        "inline": true
                    })
                }).collect::<Vec<_>>(),
                "footer": { "text": "Leash • AI Agent Visibility" },
                "timestamp": event.timestamp.to_rfc3339()
            }]
        });

        self.client
            .post(url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn send_telegram(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let token = &self.cfg.alerts.telegram.bot_token;
        let chat_id = &self.cfg.alerts.telegram.chat_id;
        let url = format!("https://api.telegram.org/bot{token}/sendMessage");
        let fields = shared_fields(event);
        let mut text = format!(
            "<b>{} Leash Alert</b>\n{}\n\n",
            severity_badge(event.threat_level),
            escape_html(&event.narrative)
        );
        for (key, value) in fields {
            text.push_str(&format!(
                "<b>{}</b>: {}\n",
                escape_html(&key),
                escape_html(&value)
            ));
        }

        let payload = json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true
        });

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

fn shared_fields(event: &SecurityEvent) -> Vec<(String, String)> {
    let process_name = event
        .process
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "-".into());
    let pid = event
        .process
        .as_ref()
        .map(|p| p.pid.to_string())
        .unwrap_or_else(|| "-".into());
    let path = event
        .file_event
        .as_ref()
        .map(|f| f.path.clone())
        .or_else(|| event.process.as_ref().map(|p| p.exe.clone()))
        .unwrap_or_else(|| "-".into());
    let mitre = event
        .mitre
        .as_ref()
        .map(|m| format!("{} {}", m.technique_id, m.name))
        .unwrap_or_else(|| "-".into());

    vec![
        ("Event Type".into(), event.event_type.to_string()),
        ("Process".into(), process_name),
        ("PID".into(), pid),
        ("Path".into(), path),
        ("MITRE Technique".into(), mitre),
        ("Timestamp".into(), event.timestamp.to_rfc3339()),
    ]
}

fn level_label(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Green => "GREEN",
        ThreatLevel::Yellow => "YELLOW",
        ThreatLevel::Orange => "ORANGE",
        ThreatLevel::Red => "RED",
        ThreatLevel::Nuclear => "NUCLEAR",
    }
}

fn severity_badge(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Green => "🟢",
        ThreatLevel::Yellow => "🟡",
        ThreatLevel::Orange => "🟠",
        ThreatLevel::Red | ThreatLevel::Nuclear => "🔴",
    }
}

fn slack_color(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Green => "#2EB67D",
        ThreatLevel::Yellow => "#ECB22E",
        ThreatLevel::Orange => "#FF8C00",
        ThreatLevel::Red | ThreatLevel::Nuclear => "#E01E5A",
    }
}

fn discord_color(level: ThreatLevel) -> u32 {
    match level {
        ThreatLevel::Green => 0x2EB67D,
        ThreatLevel::Yellow => 0xECB22E,
        ThreatLevel::Orange => 0xFF8C00,
        ThreatLevel::Red | ThreatLevel::Nuclear => 0xE01E5A,
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
