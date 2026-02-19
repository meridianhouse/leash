use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_monitor_interval_ms")]
    pub monitor_interval_ms: u64,
    #[serde(default = "default_ai_agents")]
    pub ai_agents: Vec<String>,
    #[serde(default = "default_legit_ai_parents")]
    pub legitimate_ai_parents: Vec<String>,
    #[serde(default = "default_sensitive_keywords")]
    pub sensitive_path_keywords: Vec<String>,
    #[serde(default = "default_fim_paths")]
    pub fim_paths: Vec<String>,
    #[serde(default)]
    pub protected_processes: Vec<String>,
    #[serde(default)]
    pub response: ResponseConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub egress: EgressConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    #[serde(default)]
    pub enable_sigstop: bool,
    #[serde(default = "default_response_level")]
    pub stop_min_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    #[serde(default = "default_alert_min_severity", alias = "min_level")]
    pub min_severity: String,
    #[serde(default = "default_alert_rate_limit_seconds")]
    pub rate_limit_seconds: u64,
    #[serde(default)]
    pub slack: SlackAlertConfig,
    #[serde(default)]
    pub discord: DiscordAlertConfig,
    #[serde(default)]
    pub telegram: TelegramAlertConfig,
    #[serde(default)]
    pub json_log: JsonLogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlackAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, alias = "webhook_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscordAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, alias = "webhook_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelegramAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, alias = "bot_token")]
    pub token: String,
    #[serde(default)]
    pub chat_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonLogConfig {
    #[serde(default = "default_json_log_enabled")]
    pub enabled: bool,
    #[serde(default = "default_alert_log_path")]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    #[serde(default = "default_suspicious_ports")]
    pub suspicious_ports: Vec<u16>,
    #[serde(default = "default_tor_ports")]
    pub tor_ports: Vec<u16>,
    #[serde(default = "default_exfil_domains")]
    pub exfil_domains: Vec<String>,
    #[serde(default = "default_suspicious_country_ip_prefixes")]
    pub suspicious_country_ip_prefixes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monitor_interval_ms: default_monitor_interval_ms(),
            ai_agents: default_ai_agents(),
            legitimate_ai_parents: default_legit_ai_parents(),
            sensitive_path_keywords: default_sensitive_keywords(),
            fim_paths: default_fim_paths(),
            protected_processes: vec![
                "systemd".into(),
                "sshd".into(),
                "NetworkManager".into(),
                "claude".into(),
                "codex".into(),
                "leash".into(),
            ],
            response: ResponseConfig::default(),
            alerts: AlertsConfig::default(),
            egress: EgressConfig::default(),
        }
    }
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enable_sigstop: false,
            stop_min_level: default_response_level(),
        }
    }
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            min_severity: default_alert_min_severity(),
            rate_limit_seconds: default_alert_rate_limit_seconds(),
            slack: SlackAlertConfig::default(),
            discord: DiscordAlertConfig::default(),
            telegram: TelegramAlertConfig::default(),
            json_log: JsonLogConfig::default(),
        }
    }
}

impl Default for JsonLogConfig {
    fn default() -> Self {
        Self {
            enabled: default_json_log_enabled(),
            path: default_alert_log_path(),
        }
    }
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            suspicious_ports: default_suspicious_ports(),
            tor_ports: default_tor_ports(),
            exfil_domains: default_exfil_domains(),
            suspicious_country_ip_prefixes: default_suspicious_country_ip_prefixes(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config_path = path
            .map(Path::to_path_buf)
            .unwrap_or_else(default_config_path);

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(&config_path)?;
        let mut cfg: Self = serde_yaml::from_str(&raw)?;

        cfg.alerts.json_log.path = expand_tilde(&cfg.alerts.json_log.path);
        cfg.fim_paths = cfg
            .fim_paths
            .into_iter()
            .map(|p| expand_tilde(&p))
            .collect();
        Ok(cfg)
    }
}

fn default_monitor_interval_ms() -> u64 {
    1000
}

fn default_alert_log_path() -> String {
    "~/.local/state/leash/alerts.jsonl".into()
}

fn default_json_log_enabled() -> bool {
    true
}

fn default_response_level() -> String {
    "orange".into()
}

fn default_alert_min_severity() -> String {
    "yellow".into()
}

fn default_alert_rate_limit_seconds() -> u64 {
    60
}

fn default_ai_agents() -> Vec<String> {
    vec![
        "claude".into(),
        "claude_code".into(),
        "codex".into(),
        "cursor".into(),
        "gpt".into(),
        "aider".into(),
        "cline".into(),
        "node".into(),
    ]
}

fn default_legit_ai_parents() -> Vec<String> {
    vec![
        "node".into(),
        "npm".into(),
        "bash".into(),
        "zsh".into(),
        "sh".into(),
        "tmux".into(),
        "screen".into(),
        "systemd".into(),
    ]
}

fn default_sensitive_keywords() -> Vec<String> {
    vec![
        ".ssh".into(),
        ".gnupg".into(),
        "vault".into(),
        "secret".into(),
        "token".into(),
        "credential".into(),
        ".env".into(),
        "shadow".into(),
        "sudoers".into(),
    ]
}

fn default_fim_paths() -> Vec<String> {
    vec![
        "~/.ssh".into(),
        "~/.config".into(),
        "~/.claude".into(),
        "~/.codex".into(),
        "/etc/passwd".into(),
        "/etc/shadow".into(),
        "/etc/sudoers".into(),
    ]
}

fn default_suspicious_ports() -> Vec<u16> {
    vec![4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
}

fn default_tor_ports() -> Vec<u16> {
    (9000..=9053).collect()
}

fn default_exfil_domains() -> Vec<String> {
    vec!["pastebin".into(), "transfer.sh".into(), "file.io".into()]
}

fn default_suspicious_country_ip_prefixes() -> Vec<String> {
    Vec::new()
}

fn default_config_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/leash/config.yaml")
    } else {
        PathBuf::from("/etc/leash/config.yaml")
    }
}

pub fn expand_tilde(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    input.to_string()
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn default_config_yaml_parses() {
        let parsed: Config = serde_yaml::from_str(include_str!("../config/default.yaml"))
            .expect("default.yaml should parse");
        assert_eq!(parsed.alerts.min_severity, "yellow");
        assert_eq!(parsed.alerts.rate_limit_seconds, 60);
        assert!(
            parsed
                .ai_agents
                .iter()
                .any(|item| item.eq_ignore_ascii_case("codex"))
        );
    }

    #[test]
    fn config_with_all_fields_set_parses() {
        let yaml = r#"
monitor_interval_ms: 250
ai_agents: [codex, claude]
legitimate_ai_parents: [bash, tmux]
sensitive_path_keywords: [token, secret]
fim_paths: [/etc/passwd, ~/.ssh]
protected_processes: [systemd, leash]
response:
  enable_sigstop: true
  stop_min_level: red
alerts:
  min_severity: orange
  rate_limit_seconds: 120
  slack:
    enabled: true
    url: https://hooks.slack.com/services/test
  discord:
    enabled: true
    url: https://discord.com/api/webhooks/test
  telegram:
    enabled: true
    token: token123
    chat_id: chat123
  json_log:
    enabled: true
    path: ~/.local/state/leash/custom-alerts.jsonl
egress:
  suspicious_ports: [4444, 31337]
  tor_ports: [9050, 9051]
  exfil_domains: [pastebin, file.io]
  suspicious_country_ip_prefixes: [203.0.113.]
"#;

        let parsed: Config = serde_yaml::from_str(yaml).expect("all-fields config should parse");
        assert_eq!(parsed.monitor_interval_ms, 250);
        assert_eq!(parsed.response.stop_min_level, "red");
        assert_eq!(parsed.alerts.min_severity, "orange");
        assert_eq!(parsed.alerts.rate_limit_seconds, 120);
        assert_eq!(parsed.egress.suspicious_ports, vec![4444, 31337]);
        assert_eq!(parsed.egress.suspicious_country_ip_prefixes, vec!["203.0.113."]);
    }
}
