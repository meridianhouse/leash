use crate::config::Config;
use crate::models::{SecurityEvent, ThreatLevel};
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

pub struct AlertDispatcher {
    cfg: Config,
    rx: broadcast::Receiver<SecurityEvent>,
    client: Client,
    min_severity: ThreatLevel,
    rate_limit: Duration,

    // Learning mode tracking
    learning_mode_active: Mutex<bool>,
    learning_start_time: Mutex<Instant>,

    // Per-process suppression: (agent_name, cmd_pattern) -> last_seen
    normal_commands: Mutex<HashMap<(String, String), Instant>>,

    // Deduplication: hash of (agent, cmdline_pattern) -> (timestamp, was_alerted)
    deduplication_cache: Mutex<HashMap<String, (Instant, bool)>>,

    // Process tracking for 5-minute suppression
    process_start_times: Mutex<HashMap<i32, Instant>>,

    // Rate limiting by (event_type, agent)
    rate_limit_tracker: Mutex<HashMap<(String, String), Instant>>,
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
            learning_mode_active: Mutex::new(cfg.alerts.learning_mode_hours > 0),
            learning_start_time: Mutex::new(Instant::now()),
            normal_commands: Mutex::new(HashMap::new()),
            deduplication_cache: Mutex::new(HashMap::new()),
            process_start_times: Mutex::new(HashMap::new()),
            rate_limit_tracker: Mutex::new(HashMap::new()),
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

            // Track process start time for new processes
            if let Some(ref proc) = event.process {
                self.track_process_start_time(proc.pid);
            }

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

            // Check if we should alert on this event
            if !self.should_alert(&event) {
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

    fn track_process_start_time(&self, pid: i32) {
        let mut start_times = self.process_start_times.lock().unwrap();
        if !start_times.contains_key(&pid) {
            start_times.insert(pid, Instant::now());
        }
    }

    fn is_new_process(&self, pid: i32) -> bool {
        if let Some(start_time) = self.process_start_times.lock().unwrap().get(&pid) {
            let elapsed = Instant::now().duration_since(*start_time);
            elapsed < Duration::from_secs(self.cfg.alerts.first_process_minutes * 60)
        } else {
            // Process not tracked yet, consider it new
            true
        }
    }

    fn is_known_good_command(&self, agent_name: &str, cmdline: &str) -> bool {
        let cmdline_lower = cmdline.to_ascii_lowercase();

        for kg in &self.cfg.alerts.known_good_commands {
            let pattern = kg.pattern.to_ascii_lowercase();
            let agent_filter = if kg.agent == "*" {
                true
            } else {
                agent_name
                    .to_ascii_lowercase()
                    .contains(&kg.agent.to_ascii_lowercase())
            };

            if agent_filter && cmdline_lower.contains(&pattern) {
                return true;
            }
        }
        false
    }

    fn record_normal_command(&self, agent_name: &str, cmdline: &str) {
        let cmd_pattern = extract_cmd_pattern(cmdline);
        let key = (agent_name.to_string(), cmd_pattern);
        self.normal_commands
            .lock()
            .unwrap()
            .insert(key, Instant::now());
    }

    fn is_duplicate(&self, agent_name: &str, cmdline: &str) -> bool {
        let hash = compute_event_hash(agent_name, cmdline);
        let dedup_window = Duration::from_secs(self.cfg.alerts.deduplication_hours * 3600);
        let now = Instant::now();

        let mut cache = self.deduplication_cache.lock().unwrap();

        // Clean old entries
        cache.retain(|_, (time, _)| now.duration_since(*time) < dedup_window);

        // Check if this event was already seen
        if let Some((last_time, was_alerted)) = cache.get(&hash) {
            let time_since_last = now.duration_since(*last_time);
            // If it was already alerted and within window, suppress
            if *was_alerted && time_since_last < dedup_window {
                return true;
            }
            // Update timestamp but keep the was_alerted status
            let was_alerted = *was_alerted;
            cache.insert(hash, (now, was_alerted));
            return false;
        }

        // New event, record it
        cache.insert(hash, (now, false));
        false
    }

    fn is_in_learning_mode(&self) -> bool {
        let mut learning = self.learning_mode_active.lock().unwrap();
        if !*learning {
            return false;
        }

        let start_time = *self.learning_start_time.lock().unwrap();
        let elapsed = Instant::now().duration_since(start_time);
        let learning_duration = Duration::from_secs(self.cfg.alerts.learning_mode_hours * 3600);

        if elapsed >= learning_duration {
            // Learning mode has ended
            *learning = false;
            drop(learning); // Release the lock before logging
            info!(
                "Learning mode ended after {} hours",
                self.cfg.alerts.learning_mode_hours
            );
            false
        } else {
            let remaining = learning_duration - elapsed;
            debug!(
                "Learning mode active, {} remaining",
                format_duration(remaining)
            );
            true
        }
    }

    fn should_alert(&self, event: &SecurityEvent) -> bool {
        // 1. Check severity threshold
        if event.threat_level < self.min_severity {
            debug!(
                event_type = %event.event_type,
                threat_level = ?event.threat_level,
                min_severity = ?self.min_severity,
                "suppressing alert: below severity threshold"
            );
            return false;
        }

        // 2. Check learning mode
        if self.is_in_learning_mode() {
            // In learning mode, only alert on RED+ events
            if event.threat_level < ThreatLevel::Red {
                debug!(
                    event_type = %event.event_type,
                    "suppressing alert: learning mode active"
                );
                return false;
            }
        }

        // 3. Get agent name
        let agent_name = event
            .process
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let cmdline = event
            .process
            .as_ref()
            .map(|p| p.cmdline.clone())
            .unwrap_or_default();

        // 4. Check for new AI agent process (first 5 minutes, suppress all but RED)
        if let Some(ref proc) = event.process {
            if self.is_new_process(proc.pid) && event.threat_level < ThreatLevel::Red {
                debug!(
                    pid = proc.pid,
                    process = %proc.name,
                    "suppressing alert: new process in first {} minutes",
                    self.cfg.alerts.first_process_minutes
                );
                return false;
            }
        }

        // 5. Check known-good commands
        if self.is_known_good_command(&agent_name, &cmdline) {
            debug!(
                process = %agent_name,
                cmdline = %cmdline,
                "suppressing alert: known-good command"
            );
            // Record this as a normal command
            self.record_normal_command(&agent_name, &cmdline);
            return false;
        }

        // 6. Check deduplication
        if self.is_duplicate(&agent_name, &cmdline) {
            debug!(
                process = %agent_name,
                cmdline = %cmdline,
                "suppressing alert: duplicate event within {} hours",
                self.cfg.alerts.deduplication_hours
            );
            return false;
        }

        // 7. Check rate limiting
        let event_type = event.event_type.to_string();
        let key = (event_type, agent_name.clone());
        let now = Instant::now();

        {
            let tracker = self.rate_limit_tracker.lock().unwrap();
            if let Some(last) = tracker.get(&key)
                && now.duration_since(*last) < self.rate_limit
            {
                debug!(
                    event_type = %event.event_type,
                    process = %agent_name,
                    "suppressing alert: rate limit active"
                );
                return false;
            }
        }

        // Update rate limit tracker
        self.rate_limit_tracker.lock().unwrap().insert(key, now);

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

/// Extracts a pattern from cmdline for deduplication (removes unique parts like paths with hashes)
fn extract_cmd_pattern(cmdline: &str) -> String {
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    if parts.is_empty() {
        return String::new();
    }

    // Keep the command and normalize arguments
    let cmd = parts[0];
    let normalized_cmd = std::path::Path::new(cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd);

    // For simple commands, return as-is
    let simple_commands = [
        "git", "npm", "cargo", "ls", "cat", "echo", "pwd", "whoami", "env", "ps", "top", "free",
        "df", "du", "hostname", "uname", "date", "sleep", "true", "false", "id", "which", "type",
        "read", "export", "unset", "alias", "source", "test", "mkdir", "touch", "rm", "cp", "mv",
        "chmod", "chown", "head", "tail", "less", "more", "grep", "find", "sort", "uniq", "wc",
        "tr", "sed", "awk", "cut", "paste", "diff", "cmp", "stat", "basename", "dirname",
        "realpath", "printenv",
    ];

    if simple_commands.iter().any(|&c| normalized_cmd.ends_with(c)) {
        return cmdline.to_string();
    }

    // For complex commands, normalize by keeping first 2 args max
    if parts.len() > 2 {
        format!("{} {} ...", normalized_cmd, parts[1])
    } else {
        cmdline.to_string()
    }
}

/// Computes a hash for event deduplication
fn compute_event_hash(agent_name: &str, cmdline: &str) -> String {
    let pattern = extract_cmd_pattern(cmdline);
    let input = format!("{}:{}", agent_name, pattern);
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Formats duration for logging
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
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
            start_time: None,
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

    #[test]
    fn extract_cmd_pattern_works() {
        // Simple commands
        assert_eq!(extract_cmd_pattern("git status"), "git status");
        assert_eq!(extract_cmd_pattern("ls -la"), "ls -la");

        // Complex commands with many args
        let long_cmd =
            "python /tmp/script.py --verbose --input=/tmp/file.txt --output=/tmp/out.txt";
        let pattern = extract_cmd_pattern(long_cmd);
        assert!(pattern.starts_with("python /tmp/script.py ..."));
    }

    #[test]
    fn compute_event_hash_works() {
        let hash1 = compute_event_hash("codex", "npm install");
        let hash2 = compute_event_hash("codex", "npm install");
        let hash3 = compute_event_hash("claude", "npm install");

        assert_eq!(hash1, hash2); // Same agent + same cmd = same hash
        assert_ne!(hash1, hash3); // Different agent = different hash
    }
}
