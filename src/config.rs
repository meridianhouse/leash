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
    pub alerts: AlertConfig,
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
pub struct AlertConfig {
    #[serde(default = "default_alert_min_level")]
    pub min_level: String,
    #[serde(default)]
    pub slack: SlackAlertConfig,
    #[serde(default)]
    pub discord: DiscordAlertConfig,
    #[serde(default)]
    pub telegram: TelegramAlertConfig,
    #[serde(default)]
    pub json_log: JsonLogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub webhook_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub webhook_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bot_token: String,
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
            alerts: AlertConfig::default(),
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

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            min_level: default_alert_min_level(),
            slack: SlackAlertConfig::default(),
            discord: DiscordAlertConfig::default(),
            telegram: TelegramAlertConfig::default(),
            json_log: JsonLogConfig::default(),
        }
    }
}

impl Default for SlackAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
        }
    }
}

impl Default for DiscordAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
        }
    }
}

impl Default for TelegramAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
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

fn default_alert_min_level() -> String {
    "yellow".into()
}

fn default_ai_agents() -> Vec<String> {
    vec!["claude".into(), "codex".into(), "gpt".into(), "node".into()]
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

fn default_config_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/leash/config.yaml")
    } else {
        PathBuf::from("/etc/leash/config.yaml")
    }
}

pub fn expand_tilde(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    input.to_string()
}
