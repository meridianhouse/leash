use leash::alerts::escape_html;
use leash::collector::scrub_secrets;
use leash::config::Config;
use leash::models::{EventType, ProcessInfo, SecurityEvent, ThreatLevel};

fn has_only_escaped_ampersands(value: &str) -> bool {
    let entities = ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"];
    let mut idx = 0;
    while let Some(pos) = value[idx..].find('&') {
        let absolute = idx + pos;
        let tail = &value[absolute..];
        let mut matched = false;
        for entity in entities {
            if tail.starts_with(entity) {
                idx = absolute + entity.len();
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    true
}

fn sample_strings() -> Vec<String> {
    let mut cases = Vec::new();
    for size in [0_usize, 1, 2, 3, 8, 32, 128, 1024, 8192] {
        cases.push("x".repeat(size));
    }
    cases.extend([
        "token=abc123".to_string(),
        "api_key=qwerty".to_string(),
        "sk-abcdefghijklmnopqrstuvwxyz12345".to_string(),
        "AKIAABCDEFGHIJKLMNOP".to_string(),
        "<script>alert('x')</script> & plain".to_string(),
        "multi\nline\tvalue".to_string(),
        "日本語 and ascii".to_string(),
    ]);
    cases
}

#[test]
fn property_scrub_secrets_never_increases_length() {
    for input in sample_strings() {
        let output = scrub_secrets(&input);
        assert!(
            output.len() <= input.len(),
            "input={input:?} output={output:?}"
        );
    }
}

#[test]
fn property_escape_html_never_contains_raw_angle_brackets_or_unescaped_ampersands() {
    for input in sample_strings() {
        let output = escape_html(&input);
        assert!(!output.contains('<'), "output contains <: {output:?}");
        assert!(!output.contains('>'), "output contains >: {output:?}");
        assert!(
            has_only_escaped_ampersands(&output),
            "output contains unescaped &: {output:?}"
        );
    }
}

#[test]
fn property_any_valid_yaml_config_parses_without_panic() {
    let mut config = Config::default();
    for i in 0..256 {
        config.monitor_interval_ms = 100 + i;
        config.ai_agents = vec![format!("agent{i}")];
        config.legitimate_ai_parents = vec![format!("parent{i}")];
        config.sensitive_path_keywords = vec![format!("secret{i}")];
        config.fim_paths = vec![format!("/tmp/fim{i}")];
        config.protected_processes = vec![format!("proc{i}")];

        let yaml = serde_yaml::to_string(&config).expect("serialize config yaml");
        let parsed = std::panic::catch_unwind(|| serde_yaml::from_str::<Config>(&yaml));
        assert!(parsed.is_ok(), "panic while parsing yaml: {yaml}");
    }
}

#[test]
fn property_security_event_always_serializes_to_valid_json() {
    for i in 1..=512_i32 {
        let mut event = SecurityEvent::new(
            EventType::ProcessNew,
            ThreatLevel::Yellow,
            format!("narrative-{i}"),
        );
        event.process = Some(ProcessInfo {
            pid: i,
            ppid: i - 1,
            name: format!("agent-{i}"),
            cmdline: format!("agent-{i} --run"),
            exe: format!("/usr/bin/agent-{i}"),
            cwd: "/tmp".to_string(),
            username: "user".to_string(),
            open_files: Vec::new(),
            parent_chain: Vec::new(),
        });

        let json = serde_json::to_string(&event).expect("serialize event");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse event json");
        assert!(parsed.is_object());
        assert!(parsed.get("event_type").is_some());
        assert!(parsed.get("timestamp").is_some());
    }
}
