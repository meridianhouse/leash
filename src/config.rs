use anyhow::{Context, Result, bail};
use nix::libc;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_monitor_interval_ms")]
    pub monitor_interval_ms: u64,
    #[serde(default = "default_max_history_mb")]
    pub max_history_mb: u64,
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
    pub allow_list: Vec<AllowListEntry>,
    #[serde(default)]
    pub response: ResponseConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub egress: EgressConfig,
    #[serde(default)]
    pub auth: Auth,
    #[serde(default)]
    pub datasets: DatasetConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowListEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub reason: String,
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
    #[serde(default = "default_learning_mode_hours")]
    pub learning_mode_hours: u64,
    #[serde(default)]
    pub known_good_commands: Vec<KnownGoodCommand>,
    #[serde(default = "default_deduplication_enabled")]
    pub deduplication_enabled: bool,
    #[serde(default = "default_deduplication_window_seconds")]
    pub deduplication_window_seconds: u64,
    #[serde(default = "default_first_process_minutes")]
    pub first_process_minutes: u64,
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
pub struct KnownGoodCommand {
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub agent: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Auth {
    #[serde(default)]
    pub stop_password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetConfig {
    #[serde(default = "default_datasets_enabled")]
    pub enabled: bool,
    #[serde(default = "default_datasets_cache_dir")]
    pub cache_dir: String,
    #[serde(default = "default_datasets_auto_update")]
    pub auto_update: bool,
    #[serde(default = "default_datasets_update_interval_days")]
    pub update_interval_days: u64,
    #[serde(default = "default_lolrmm_url")]
    pub lolrmm_url: String,
    #[serde(default = "default_loldrivers_url")]
    pub loldrivers_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monitor_interval_ms: default_monitor_interval_ms(),
            max_history_mb: default_max_history_mb(),
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
            allow_list: Vec::new(),
            response: ResponseConfig::default(),
            alerts: AlertsConfig::default(),
            egress: EgressConfig::default(),
            auth: Auth::default(),
            datasets: DatasetConfig::default(),
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
            learning_mode_hours: default_learning_mode_hours(),
            known_good_commands: Vec::new(),
            deduplication_enabled: default_deduplication_enabled(),
            deduplication_window_seconds: default_deduplication_window_seconds(),
            first_process_minutes: default_first_process_minutes(),
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

impl Default for DatasetConfig {
    fn default() -> Self {
        Self {
            enabled: default_datasets_enabled(),
            cache_dir: default_datasets_cache_dir(),
            auto_update: default_datasets_auto_update(),
            update_interval_days: default_datasets_update_interval_days(),
            lolrmm_url: default_lolrmm_url(),
            loldrivers_url: default_loldrivers_url(),
        }
    }
}

impl Config {
    /// Parses a [`Config`] from YAML content and applies normalization/validation.
    pub fn from_yaml_str(raw: &str) -> Result<Self> {
        let mut cfg: Self = serde_yaml::from_str(raw).context("invalid YAML")?;

        cfg.alerts.json_log.path = expand_tilde(&cfg.alerts.json_log.path);
        cfg.datasets.cache_dir = expand_tilde(&cfg.datasets.cache_dir);
        cfg.fim_paths = cfg
            .fim_paths
            .into_iter()
            .map(|p| expand_tilde(&p))
            .collect();
        cfg.validate().context("invalid config values")?;
        Ok(cfg)
    }

    pub fn load(path: Option<&Path>) -> Result<Self> {
        let config_path = path
            .map(Path::to_path_buf)
            .unwrap_or_else(default_config_path);

        if !config_path.exists() {
            eprintln!(
                "Warning: config file not found at {}. Run `leash init` to create a starter config.",
                config_path.display()
            );
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read config file: {}", config_path.display()))?;
        let cfg = Self::from_yaml_str(&raw)
            .with_context(|| format!("invalid YAML in config file {}", config_path.display()))?;
        cfg.print_startup_warnings();

        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        if self.monitor_interval_ms < 100 {
            errors.push(format!(
                "monitor_interval_ms must be at least 100 (got {})",
                self.monitor_interval_ms
            ));
        }
        if self.datasets.update_interval_days == 0 {
            errors.push("datasets.update_interval_days must be at least 1".to_string());
        }
        for (name, url) in [
            ("datasets.lolrmm_url", self.datasets.lolrmm_url.trim()),
            (
                "datasets.loldrivers_url",
                self.datasets.loldrivers_url.trim(),
            ),
        ] {
            if !url.is_empty() && !is_valid_https_url(url) {
                errors.push(format!(
                    "{name} must start with https:// (got '{url}')"
                ));
            }
        }

        validate_level(&self.alerts.min_severity, "alerts.min_severity")?;
        validate_level(&self.response.stop_min_level, "response.stop_min_level")?;

        if !has_enabled_alert_sink(&self.alerts) {
            errors.push(
                "alerts config must enable at least one sink: alerts.json_log, alerts.slack, alerts.discord, or alerts.telegram".to_string(),
            );
        }
        if self.alerts.json_log.enabled && self.alerts.json_log.path.trim().is_empty() {
            errors.push("alerts.json_log.enabled is true but alerts.json_log.path is empty".into());
        }
        if self.alerts.slack.enabled && self.alerts.slack.url.trim().is_empty() {
            errors.push("alerts.slack.enabled is true but alerts.slack.url is empty".into());
        }
        if self.alerts.discord.enabled && self.alerts.discord.url.trim().is_empty() {
            errors.push("alerts.discord.enabled is true but alerts.discord.url is empty".into());
        }
        if self.alerts.telegram.enabled && self.alerts.telegram.token.trim().is_empty() {
            errors
                .push("alerts.telegram.enabled is true but alerts.telegram.token is empty".into());
        }
        if self.alerts.telegram.enabled && self.alerts.telegram.chat_id.trim().is_empty() {
            errors.push(
                "alerts.telegram.enabled is true but alerts.telegram.chat_id is empty".into(),
            );
        }

        for (name, url) in [
            ("alerts.slack.url", self.alerts.slack.url.trim()),
            ("alerts.discord.url", self.alerts.discord.url.trim()),
        ] {
            if !url.is_empty() && !is_valid_http_or_https_url(url) {
                errors.push(format!(
                    "{name} must start with http:// or https:// (got '{url}')"
                ));
            }
        }

        for (index, entry) in self.allow_list.iter().enumerate() {
            if entry.name.trim().is_empty() {
                errors.push(format!("allow_list[{index}].name cannot be empty"));
            }
        }

        if !errors.is_empty() {
            bail!("{}", errors.join("\n"));
        }
        Ok(())
    }

    fn print_startup_warnings(&self) {
        for warning in self.startup_warnings() {
            eprintln!("Warning: {warning}");
        }
    }

    fn startup_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.alerts.slack.enabled {
            if self.alerts.slack.url.trim().is_empty() {
                warnings.push(
                    "alerts.slack.enabled is true but alerts.slack.url is empty. Slack webhook URL should match https://hooks.slack.com/services/<team>/<channel>/<token>.".to_string(),
                );
            } else if !is_valid_https_url(&self.alerts.slack.url) {
                warnings.push(
                    format!(
                        "alerts.slack.url is not a valid HTTPS URL: '{}'. Slack webhook URL should match https://hooks.slack.com/services/<team>/<channel>/<token>.",
                        self.alerts.slack.url.trim()
                    ),
                );
            } else if !self
                .alerts
                .slack
                .url
                .to_ascii_lowercase()
                .starts_with("https://hooks.slack.com/")
            {
                warnings.push(
                    format!(
                        "alerts.slack.url does not look like a Slack webhook: '{}'. Slack webhook URL should match https://hooks.slack.com/services/<team>/<channel>/<token>.",
                        self.alerts.slack.url.trim()
                    ),
                );
            }
        }

        if self.alerts.discord.enabled {
            if self.alerts.discord.url.trim().is_empty() {
                warnings.push(
                    "alerts.discord.enabled is true but alerts.discord.url is empty. Discord webhook URL should match https://discord.com/api/webhooks/<id>/<token>.".to_string(),
                );
            } else if !is_valid_https_url(&self.alerts.discord.url) {
                warnings.push(
                    format!(
                        "alerts.discord.url is not a valid HTTPS URL: '{}'. Discord webhook URL should match https://discord.com/api/webhooks/<id>/<token>.",
                        self.alerts.discord.url.trim()
                    ),
                );
            } else if !self
                .alerts
                .discord
                .url
                .to_ascii_lowercase()
                .starts_with("https://discord.com/api/webhooks/")
                && !self
                    .alerts
                    .discord
                    .url
                    .to_ascii_lowercase()
                    .starts_with("https://discordapp.com/api/webhooks/")
            {
                warnings.push(
                    format!(
                        "alerts.discord.url does not look like a Discord webhook: '{}'. Discord webhook URL should match https://discord.com/api/webhooks/<id>/<token>.",
                        self.alerts.discord.url.trim()
                    ),
                );
            }
        }

        if self.alerts.telegram.enabled {
            if !is_valid_telegram_token(&self.alerts.telegram.token) {
                warnings.push(
                    "alerts.telegram.token appears invalid. Telegram bot token should look like 123456789:AA... with digits, a colon, and a long secret.".to_string(),
                );
            }
            if !is_numeric_chat_id(&self.alerts.telegram.chat_id) {
                warnings.push(
                    "alerts.telegram.chat_id must be numeric (example: 123456789 or -1001234567890).".to_string(),
                );
            }
        }

        warnings
    }
}

fn default_monitor_interval_ms() -> u64 {
    1000
}

fn default_alert_log_path() -> String {
    "~/.local/state/leash/alerts.jsonl".into()
}

fn default_max_history_mb() -> u64 {
    100
}

fn default_json_log_enabled() -> bool {
    true
}

fn default_response_level() -> String {
    "orange".into()
}

fn default_alert_min_severity() -> String {
    "orange".into()
}

fn default_alert_rate_limit_seconds() -> u64 {
    300
}

fn default_learning_mode_hours() -> u64 {
    24
}

fn default_deduplication_enabled() -> bool {
    true
}

fn default_deduplication_window_seconds() -> u64 {
    300
}

fn default_first_process_minutes() -> u64 {
    5
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

fn default_datasets_enabled() -> bool {
    true
}

fn default_datasets_cache_dir() -> String {
    "~/.config/leash/datasets".into()
}

fn default_datasets_auto_update() -> bool {
    true
}

fn default_datasets_update_interval_days() -> u64 {
    7
}

fn default_lolrmm_url() -> String {
    "https://lolrmm.io/api/rmm_tools.json".into()
}

fn default_loldrivers_url() -> String {
    "https://www.loldrivers.io/api/drivers.json".into()
}

fn default_config_path() -> PathBuf {
    trusted_home_dir()
        .map(|home| home.join(".config/leash/config.yaml"))
        .unwrap_or_else(|| PathBuf::from("/etc/leash/config.yaml"))
}

pub fn expand_tilde(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("~/")
        && let Some(home) = trusted_home_dir()
    {
        return home.join(rest).display().to_string();
    }
    input.to_string()
}

fn trusted_home_dir() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if is_valid_home_path(&path) {
                return Some(path);
            }
        }
    }

    lookup_home_from_passwd().filter(|path| is_valid_home_path(path))
}

fn is_valid_home_path(path: &Path) -> bool {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return false;
    }
    let forbidden = [
        Path::new("/"),
        Path::new("/etc"),
        Path::new("/bin"),
        Path::new("/sbin"),
        Path::new("/usr"),
        Path::new("/var"),
        Path::new("/tmp"),
        Path::new("/proc"),
        Path::new("/dev"),
        Path::new("/sys"),
        Path::new("/run"),
    ];
    if forbidden.contains(&path) {
        return false;
    }

    path.starts_with("/home/") || path.starts_with("/Users/") || path == Path::new("/root")
}

fn lookup_home_from_passwd() -> Option<PathBuf> {
    // SAFETY: libc calls are used with valid pointers and owned buffers.
    unsafe {
        let uid = libc::geteuid();
        let mut passwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buffer = vec![0u8; 16 * 1024];
        let rc = libc::getpwuid_r(
            uid,
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() || passwd.pw_dir.is_null() {
            return None;
        }
        let home = CStr::from_ptr(passwd.pw_dir).to_string_lossy().into_owned();
        Some(PathBuf::from(home))
    }
}

fn validate_level(raw: &str, field_name: &str) -> Result<()> {
    match raw.to_ascii_lowercase().as_str() {
        "green" | "yellow" | "orange" | "red" | "nuclear" => Ok(()),
        _ => {
            bail!("{field_name} must be one of: green, yellow, orange, red, nuclear (got '{raw}')")
        }
    }
}

fn is_valid_https_url(raw: &str) -> bool {
    let Ok(parsed) = Url::parse(raw.trim()) else {
        return false;
    };
    parsed.scheme().eq_ignore_ascii_case("https") && parsed.host_str().is_some()
}

fn is_valid_http_or_https_url(raw: &str) -> bool {
    let Ok(parsed) = Url::parse(raw.trim()) else {
        return false;
    };
    (parsed.scheme().eq_ignore_ascii_case("http") || parsed.scheme().eq_ignore_ascii_case("https"))
        && parsed.host_str().is_some()
}

fn has_enabled_alert_sink(alerts: &AlertsConfig) -> bool {
    alerts.json_log.enabled
        || alerts.slack.enabled
        || alerts.discord.enabled
        || alerts.telegram.enabled
}

fn is_valid_telegram_token(raw: &str) -> bool {
    let token = raw.trim();
    let Some((bot_id, secret)) = token.split_once(':') else {
        return false;
    };
    bot_id.len() >= 6
        && bot_id.chars().all(|ch| ch.is_ascii_digit())
        && secret.len() >= 20
        && secret
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

fn is_numeric_chat_id(raw: &str) -> bool {
    let value = raw.trim();
    if value.is_empty() {
        return false;
    }

    let digits = if let Some(rest) = value.strip_prefix('-') {
        rest
    } else {
        value
    };

    !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{
        Config, is_numeric_chat_id, is_valid_home_path, is_valid_https_url, is_valid_telegram_token,
    };
    use std::path::Path;

    #[test]
    fn default_config_yaml_parses() {
        let parsed: Config = serde_yaml::from_str(include_str!("../config/default.yaml"))
            .expect("default.yaml should parse");
        assert_eq!(parsed.alerts.min_severity, "orange");
        assert_eq!(parsed.alerts.rate_limit_seconds, 300);
        assert!(!parsed.alerts.deduplication_enabled);
        assert_eq!(parsed.alerts.deduplication_window_seconds, 300);
        assert!(
            parsed
                .ai_agents
                .iter()
                .any(|item| item.eq_ignore_ascii_case("codex"))
        );
        assert!(parsed.datasets.enabled);
        assert_eq!(parsed.datasets.update_interval_days, 7);
    }

    #[test]
    fn config_with_all_fields_set_parses() {
        let yaml = r#"
monitor_interval_ms: 250
max_history_mb: 200
ai_agents: [codex, claude]
legitimate_ai_parents: [bash, tmux]
sensitive_path_keywords: [token, secret]
fim_paths: [/etc/passwd, ~/.ssh]
protected_processes: [systemd, leash]
allow_list:
  - name: codex
    reason: approved local dev agent
response:
  enable_sigstop: true
  stop_min_level: red
alerts:
  min_severity: orange
  rate_limit_seconds: 120
  deduplication_enabled: true
  deduplication_window_seconds: 3600
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
auth:
  stop_password_hash: 9f86d081884c7d659a2feaa0c55ad015
datasets:
  enabled: true
  cache_dir: ~/.config/leash/datasets
  auto_update: true
  update_interval_days: 7
  lolrmm_url: https://lolrmm.io/api/rmm_tools.json
  loldrivers_url: https://www.loldrivers.io/api/drivers.json
"#;

        let parsed: Config = serde_yaml::from_str(yaml).expect("all-fields config should parse");
        assert_eq!(parsed.monitor_interval_ms, 250);
        assert_eq!(parsed.max_history_mb, 200);
        assert_eq!(parsed.allow_list.len(), 1);
        assert_eq!(parsed.allow_list[0].name, "codex");
        assert_eq!(parsed.allow_list[0].reason, "approved local dev agent");
        assert_eq!(parsed.response.stop_min_level, "red");
        assert_eq!(parsed.alerts.min_severity, "orange");
        assert_eq!(parsed.alerts.rate_limit_seconds, 120);
        assert!(parsed.alerts.deduplication_enabled);
        assert_eq!(parsed.alerts.deduplication_window_seconds, 3600);
        assert_eq!(parsed.egress.suspicious_ports, vec![4444, 31337]);
        assert_eq!(
            parsed.egress.suspicious_country_ip_prefixes,
            vec!["203.0.113."]
        );
        assert_eq!(
            parsed.auth.stop_password_hash,
            "9f86d081884c7d659a2feaa0c55ad015"
        );
        assert!(parsed.datasets.enabled);
        assert!(parsed.datasets.auto_update);
        assert_eq!(parsed.datasets.update_interval_days, 7);
    }

    #[test]
    fn webhook_and_telegram_validation_helpers_work() {
        assert!(is_valid_https_url(
            "https://hooks.slack.com/services/T/B/KEY"
        ));
        assert!(!is_valid_https_url(
            "http://hooks.slack.com/services/T/B/KEY"
        ));
        assert!(is_valid_telegram_token(
            "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        ));
        assert!(!is_valid_telegram_token("token123"));
        assert!(is_numeric_chat_id("123456"));
        assert!(is_numeric_chat_id("-100123456"));
        assert!(!is_numeric_chat_id("chat123"));
    }

    #[test]
    fn home_validation_rejects_system_paths() {
        assert!(!is_valid_home_path(Path::new("")));
        assert!(!is_valid_home_path(Path::new("/etc")));
        assert!(!is_valid_home_path(Path::new("/tmp")));
        assert!(is_valid_home_path(Path::new("/home/ryan")));
    }

    #[test]
    fn webhook_warnings_include_invalid_urls() {
        let mut cfg = Config::default();
        cfg.alerts.slack.enabled = true;
        cfg.alerts.slack.url = "http://bad.example/slack".into();
        cfg.alerts.discord.enabled = true;
        cfg.alerts.discord.url = "not-a-url".into();

        let warnings = cfg.startup_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("http://bad.example/slack"))
        );
        assert!(warnings.iter().any(|w| w.contains("not-a-url")));
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("https://hooks.slack.com/services/<team>/<channel>/<token>"))
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("https://discord.com/api/webhooks/<id>/<token>"))
        );
    }

    #[test]
    fn rejects_scan_interval_under_100ms() {
        let err = Config::from_yaml_str(
            r#"
monitor_interval_ms: 99
alerts:
  json_log:
    enabled: true
"#,
        )
        .expect_err("interval below 100ms should fail validation");
        assert!(
            err.to_string()
                .contains("monitor_interval_ms must be at least 100")
        );
    }

    #[test]
    fn rejects_webhook_urls_without_http_or_https_scheme() {
        let err = Config::from_yaml_str(
            r#"
alerts:
  slack:
    enabled: true
    url: ftp://hooks.slack.com/services/T/B/KEY
"#,
        )
        .expect_err("invalid scheme should fail validation");
        assert!(
            err.to_string()
                .contains("alerts.slack.url must start with http:// or https://")
        );
    }

    #[test]
    fn rejects_empty_alert_configuration() {
        let err = Config::from_yaml_str(
            r#"
alerts:
  json_log:
    enabled: false
  slack:
    enabled: false
  discord:
    enabled: false
  telegram:
    enabled: false
"#,
        )
        .expect_err("all alert sinks disabled should fail validation");
        assert!(
            err.to_string()
                .contains("alerts config must enable at least one sink")
        );
    }
}
