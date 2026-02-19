use crate::config::Config;
use crate::models::{SecurityEvent, ThreatLevel};
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub struct AlertDispatcher {
    cfg: Config,
    rx: broadcast::Receiver<SecurityEvent>,
    client: Client,
    min_severity: ThreatLevel,
    rate_limit: Duration,
    last_alert_by_source: HashMap<(String, i32), Instant>,
}

impl AlertDispatcher {
    /// Creates an alert dispatcher configured for severity filtering, rate limiting, and sink delivery.
    pub fn new(
        cfg: Config,
        rx: broadcast::Receiver<SecurityEvent>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            min_severity: parse_level(&cfg.alerts.min_severity),
            rate_limit: Duration::from_secs(cfg.alerts.rate_limit_seconds),
            last_alert_by_source: HashMap::new(),
            cfg,
            rx,
            client: Client::builder().build()?,
        })
    }

    /// Consumes security events from the channel and forwards eligible alerts to configured sinks.
    pub async fn run(mut self) {
        loop {
            let event = match self.rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let scrubbed_event = scrub_event(&event);

            if self.cfg.alerts.json_log.enabled
                && let Err(err) = self.write_local_log(&scrubbed_event)
            {
                error!(?err, "failed to write alert log");
            }

            if event.allowed {
                info!(
                    event_type = %event.event_type,
                    reason = %event.allowed_reason.as_deref().unwrap_or("allow_list"),
                    "skipping alerts for allow-listed event"
                );
                continue;
            }

            if event.threat_level < self.min_severity || !self.should_send_for_event_type(&event) {
                continue;
            }

            if self.cfg.alerts.slack.enabled
                && !self.cfg.alerts.slack.url.is_empty()
                && let Err(err) = self
                    .send_slack(&self.cfg.alerts.slack.url, &scrubbed_event)
                    .await
            {
                warn!(?err, "slack delivery failed");
            }

            if self.cfg.alerts.discord.enabled
                && !self.cfg.alerts.discord.url.is_empty()
                && let Err(err) = self
                    .send_discord(&self.cfg.alerts.discord.url, &scrubbed_event)
                    .await
            {
                warn!(?err, "discord delivery failed");
            }

            if self.cfg.alerts.telegram.enabled
                && !self.cfg.alerts.telegram.token.is_empty()
                && !self.cfg.alerts.telegram.chat_id.is_empty()
                && let Err(err) = self.send_telegram(&scrubbed_event).await
            {
                warn!(?err, "telegram delivery failed");
            }
        }
    }

    fn should_send_for_event_type(&mut self, event: &SecurityEvent) -> bool {
        let now = Instant::now();
        let event_type = event.event_type.to_string();
        let pid = event.process.as_ref().map(|proc| proc.pid).unwrap_or(-1);
        let key = (event_type, pid);

        if let Some(last) = self.last_alert_by_source.get(&key)
            && now.duration_since(*last) < self.rate_limit
        {
            return false;
        }

        self.last_alert_by_source.insert(key, now);
        true
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
        let payload = build_slack_payload(event);

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
        let payload = build_discord_payload(event);

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
        let payload = build_telegram_payload(event, chat_id);

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
        .map(|p| scrub_secrets(&p.name))
        .unwrap_or_else(|| "-".into());
    let pid = event
        .process
        .as_ref()
        .map(|p| p.pid.to_string())
        .unwrap_or_else(|| "-".into());
    let path = event
        .file_event
        .as_ref()
        .map(|f| scrub_secrets(&f.path))
        .or_else(|| event.process.as_ref().map(|p| scrub_secrets(&p.exe)))
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

fn build_slack_payload(event: &SecurityEvent) -> serde_json::Value {
    let details = event_details(event);
    json!({
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
                        { "type": "mrkdwn", "text": event.timestamp.to_rfc3339() },
                        { "type": "mrkdwn", "text": "Leash • AI Agent Visibility" }
                    ]
                }
            ]
        }]
    })
}

fn build_discord_payload(event: &SecurityEvent) -> serde_json::Value {
    let details = event_details(event);
    json!({
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
    })
}

fn build_telegram_payload(event: &SecurityEvent, chat_id: &str) -> serde_json::Value {
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

    json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": true
    })
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

/// Escapes Telegram HTML meta-characters in an alert field value.
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn scrub_event(event: &SecurityEvent) -> SecurityEvent {
    let mut out = event.clone();
    out.narrative = scrub_secrets(&out.narrative);
    out.allowed_reason = out.allowed_reason.as_ref().map(|v| scrub_secrets(v));

    if let Some(process) = out.process.as_mut() {
        process.name = scrub_secrets(&process.name);
        process.cmdline = scrub_secrets(&process.cmdline);
        process.exe = scrub_secrets(&process.exe);
        process.cwd = scrub_secrets(&process.cwd);
        process.open_files = process
            .open_files
            .iter()
            .map(|path| scrub_secrets(path))
            .collect();
        process.parent_chain = process
            .parent_chain
            .iter()
            .map(|entry| scrub_secrets(entry))
            .collect();
    }

    if let Some(file_event) = out.file_event.as_mut() {
        file_event.path = scrub_secrets(&file_event.path);
    }

    if let Some(enrichment) = out.enrichment.as_mut() {
        enrichment.full_cmdline = scrub_secrets(&enrichment.full_cmdline);
        enrichment.working_dir = scrub_secrets(&enrichment.working_dir);
        enrichment.open_fds = enrichment
            .open_fds
            .iter()
            .map(|path| scrub_secrets(path))
            .collect();
        enrichment.env = enrichment
            .env
            .iter()
            .map(|(k, v)| (k.clone(), scrub_secrets(v)))
            .collect();
    }

    out
}

/// Redacts common API keys and credential assignments from untrusted text.
pub fn scrub_secrets(input: &str) -> String {
    let mut output = redact_prefixed_alnum_secret(input, "sk-", 20);
    for prefix in ["AKIA", "ABIA", "ACCA", "ASIA"] {
        output = redact_fixed_alnum_secret(&output, prefix, 16);
    }
    redact_assignment_secrets(&output)
}

fn redact_prefixed_alnum_secret(input: &str, prefix: &str, min_tail_len: usize) -> String {
    let mut output = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < input.len() {
        let Some(found) = input[idx..].find(prefix) else {
            output.push_str(&input[idx..]);
            break;
        };
        let start = idx + found;
        output.push_str(&input[idx..start]);

        let tail_start = start + prefix.len();
        let tail_len = input[tail_start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric())
            .count();
        if tail_len >= min_tail_len {
            output.push_str("[REDACTED]");
            idx = tail_start + tail_len;
        } else {
            output.push_str(prefix);
            idx = tail_start;
        }
    }
    output
}

fn redact_fixed_alnum_secret(input: &str, prefix: &str, tail_len: usize) -> String {
    let mut output = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < input.len() {
        let Some(found) = input[idx..].find(prefix) else {
            output.push_str(&input[idx..]);
            break;
        };
        let start = idx + found;
        output.push_str(&input[idx..start]);

        let secret_start = start + prefix.len();
        let tail = input[secret_start..]
            .chars()
            .take(tail_len)
            .collect::<String>();
        if tail.chars().count() == tail_len
            && tail
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        {
            output.push_str("[REDACTED]");
            idx = secret_start + tail_len;
        } else {
            output.push_str(prefix);
            idx = secret_start;
        }
    }
    output
}

fn redact_assignment_secrets(input: &str) -> String {
    let keys = ["api_key", "secret", "token", "password"];
    let mut output = String::with_capacity(input.len());
    let mut idx = 0;

    while idx < input.len() {
        let current = input[idx..].chars().next().unwrap_or_default();
        if current.is_ascii_alphabetic() {
            let key_start = idx;
            while idx < input.len() {
                let ch = input[idx..].chars().next().unwrap_or_default();
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    idx += ch.len_utf8();
                } else {
                    break;
                }
            }
            let key = &input[key_start..idx];
            if idx < input.len()
                && input[idx..].starts_with('=')
                && keys
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
            {
                output.push_str(key);
                output.push('=');
                idx += 1;
                let secret_start = idx;
                while idx < input.len() {
                    let ch = input[idx..].chars().next().unwrap_or_default();
                    if ch.is_ascii_whitespace() || ch == '&' {
                        break;
                    }
                    idx += ch.len_utf8();
                }
                let secret_len = idx.saturating_sub(secret_start);
                if secret_len >= "[REDACTED]".len() {
                    output.push_str("[REDACTED]");
                } else {
                    output.push_str(&"*".repeat(secret_len));
                }
                continue;
            }
            output.push_str(key);
            continue;
        }

        output.push(current);
        idx += current.len_utf8();
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::models::{EventType, ProcessInfo, SecurityEvent, ThreatLevel};
    use std::time::{Duration, Instant};
    use tokio::sync::broadcast;

    fn sample_event() -> SecurityEvent {
        let mut event = SecurityEvent::new(
            EventType::CredentialAccess,
            ThreatLevel::Red,
            "credential access detected".to_string(),
        );
        event.process = Some(ProcessInfo {
            pid: 4242,
            ppid: 1111,
            name: "codex".to_string(),
            cmdline: "codex run".to_string(),
            exe: "/usr/local/bin/codex".to_string(),
            cwd: "/tmp".to_string(),
            username: "user".to_string(),
            open_files: Vec::new(),
            parent_chain: Vec::new(),
        });
        event
    }

    #[test]
    fn slack_payload_is_valid_json() {
        let payload = build_slack_payload(&sample_event());
        let serialized = serde_json::to_string(&payload).expect("serialize slack payload");
        let parsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("parse slack payload json");
        assert!(parsed.get("text").is_some());
        let attachments = parsed["attachments"]
            .as_array()
            .expect("slack attachments must be an array");
        assert!(
            !attachments.is_empty(),
            "slack attachments should not be empty"
        );
        assert!(
            attachments[0]["blocks"].is_array(),
            "first slack attachment should have blocks array"
        );
    }

    #[test]
    fn discord_payload_is_valid_json() {
        let payload = build_discord_payload(&sample_event());
        let serialized = serde_json::to_string(&payload).expect("serialize discord payload");
        let parsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("parse discord payload json");
        let embeds = parsed["embeds"]
            .as_array()
            .expect("discord embeds must be an array");
        assert!(!embeds.is_empty(), "discord embeds should not be empty");
        assert!(
            embeds[0].get("color").is_some(),
            "first discord embed should include color"
        );
    }

    #[test]
    fn telegram_payload_is_valid_json() {
        let payload = build_telegram_payload(&sample_event(), "123456");
        let serialized = serde_json::to_string(&payload).expect("serialize telegram payload");
        let parsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("parse telegram payload json");
        assert_eq!(parsed["chat_id"], "123456");
        assert!(
            parsed["text"].is_string(),
            "telegram payload text must be a string"
        );
        assert_eq!(parsed["parse_mode"], "HTML");
    }

    fn dispatcher() -> AlertDispatcher {
        let cfg = Config::default();
        let (_, rx) = broadcast::channel::<SecurityEvent>(4);
        AlertDispatcher::new(cfg, rx).expect("dispatcher should initialize in test")
    }

    #[test]
    fn rate_limiter_blocks_duplicate_events_within_window() {
        let mut dispatcher = dispatcher();
        let event = sample_event();

        assert!(dispatcher.should_send_for_event_type(&event));
        assert!(!dispatcher.should_send_for_event_type(&event));
    }

    #[test]
    fn rate_limiter_allows_events_after_window_expires() {
        let mut dispatcher = dispatcher();
        let event = sample_event();
        let key = (
            event.event_type.to_string(),
            event.process.as_ref().map(|p| p.pid).unwrap_or(-1),
        );

        assert!(dispatcher.should_send_for_event_type(&event));
        dispatcher.last_alert_by_source.insert(
            key,
            Instant::now() - dispatcher.rate_limit - Duration::from_millis(1),
        );

        assert!(dispatcher.should_send_for_event_type(&event));
    }

    #[test]
    fn rate_limiter_isolated_by_pid() {
        let mut dispatcher = dispatcher();
        let event_a = sample_event();
        let mut event_b = sample_event();
        event_b.process.as_mut().expect("process must exist").pid = 9001;

        assert!(dispatcher.should_send_for_event_type(&event_a));
        assert!(!dispatcher.should_send_for_event_type(&event_a));
        assert!(dispatcher.should_send_for_event_type(&event_b));
    }

    #[test]
    fn scrub_secrets_redacts_known_patterns() {
        let input = "token=shhh sk-abcdefghijklmnopqrstuvwxyz12345 AKIAABCDEFGHIJKLMNOP";
        let output = scrub_secrets(input);
        assert!(!output.contains("token=shhh"));
        assert!(!output.contains("AKIAABCDEFGHIJKLMNOP"));
        assert!(!output.contains("sk-abcdefghijklmnopqrstuvwxyz12345"));
        assert!(output.contains("[REDACTED]"));
    }
}
