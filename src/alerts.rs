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

            if self.cfg.alerts.slack.enabled && !self.cfg.alerts.slack.url.is_empty() {
                if let Err(err) = self.send_slack(&self.cfg.alerts.slack.url, &event).await {
                    warn!(?err, "slack delivery failed");
                }
            }

            if self.cfg.alerts.discord.enabled && !self.cfg.alerts.discord.url.is_empty() {
                if let Err(err) = self
                    .send_discord(&self.cfg.alerts.discord.url, &event)
                    .await
                {
                    warn!(?err, "discord delivery failed");
                }
            }

            if self.cfg.alerts.telegram.enabled
                && !self.cfg.alerts.telegram.token.is_empty()
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
        let details = event_details(event);
        let payload = json!({
            "text": format!("[{}] {}", level_label(event.threat_level), event.narrative),
            "attachments": [{
                "color": slack_color(event.threat_level),
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!("*Leash Alert* {} *{}*\n{}", severity_badge(event.threat_level), level_label(event.threat_level), event.narrative)
                        },
                        "fields": [
                            { "type": "mrkdwn", "text": format!("*Type*\n`{}`", details.event_type) },
                            { "type": "mrkdwn", "text": format!("*Process*\n`{}`", details.process) },
                            { "type": "mrkdwn", "text": format!("*PID*\n`{}`", details.pid) },
                            { "type": "mrkdwn", "text": format!("*Path*\n`{}`", details.path) },
                            { "type": "mrkdwn", "text": format!("*MITRE Technique*\n`{}`", details.mitre_technique) }
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [
                            { "type": "mrkdwn", "text": format!("{}", event.timestamp.to_rfc3339()) },
                            { "type": "mrkdwn", "text": "Leash • AI Agent Visibility" }
                        ]
                    }
                ]
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
        let details = event_details(event);
        let payload = json!({
            "embeds": [{
                "title": format!("Leash Alert {}", severity_badge(event.threat_level)),
                "description": event.narrative,
                "color": discord_color(event.threat_level),
                "fields": [
                    { "name": "Event", "value": details.event_type, "inline": true },
                    { "name": "Process", "value": details.process, "inline": true },
                    { "name": "PID", "value": details.pid, "inline": true },
                    { "name": "Path", "value": details.path, "inline": false },
                    { "name": "MITRE ID", "value": details.mitre_id, "inline": true }
                ],
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
        let token = &self.cfg.alerts.telegram.token;
        let chat_id = &self.cfg.alerts.telegram.chat_id;
        let url = format!("https://api.telegram.org/bot{token}/sendMessage");
        let details = event_details(event);

        let text = format!(
            "<b>{} Leash Alert ({})</b>\n{}\n\n<b>Event:</b> <code>{}</code>\n<b>Process:</b> <code>{}</code>\n<b>PID:</b> <code>{}</code>\n<b>Path:</b> <code>{}</code>\n<b>MITRE ID:</b> <code>{}</code>\n<b>Timestamp:</b> <code>{}</code>",
            severity_badge(event.threat_level),
            level_label(event.threat_level),
            escape_html(&event.narrative),
            escape_html(&details.event_type),
            escape_html(&details.process),
            escape_html(&details.pid),
            escape_html(&details.path),
            escape_html(&details.mitre_id),
            escape_html(&event.timestamp.to_rfc3339())
        );

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

struct EventDetails {
    event_type: String,
    process: String,
    pid: String,
    path: String,
    mitre_id: String,
    mitre_technique: String,
}

fn event_details(event: &SecurityEvent) -> EventDetails {
    let process = event
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
    let mitre_id = event
        .mitre
        .iter()
        .map(|m| m.technique_id.clone())
        .collect::<Vec<_>>()
        .join(", ")
        .trim()
        .to_string();
    let mitre_id = if mitre_id.is_empty() {
        "-".to_string()
    } else {
        mitre_id
    };
    let mitre_technique = event
        .mitre
        .iter()
        .map(|m| format!("{} {}", m.technique_id, m.name))
        .collect::<Vec<_>>()
        .join("; ")
        .trim()
        .to_string();
    let mitre_technique = if mitre_technique.is_empty() {
        "-".to_string()
    } else {
        mitre_technique
    };

    EventDetails {
        event_type: event.event_type.to_string(),
        process,
        pid,
        path,
        mitre_id,
        mitre_technique,
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
        ThreatLevel::Green => "good",
        ThreatLevel::Yellow | ThreatLevel::Orange => "warning",
        ThreatLevel::Red | ThreatLevel::Nuclear => "danger",
    }
}

fn discord_color(level: ThreatLevel) -> u32 {
    match level {
        ThreatLevel::Green => 0x00ff00,
        ThreatLevel::Yellow => 0xffff00,
        ThreatLevel::Orange => 0xff8800,
        ThreatLevel::Red | ThreatLevel::Nuclear => 0xff0000,
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
