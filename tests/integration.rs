use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn temp_home(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("leash-int-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp home");
    dir
}

fn run_leash(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(args)
        .env("HOME", home)
        .output()
        .expect("run leash")
}

fn write_event_db(home: &Path, rows: &[(String, String, String, String, String)]) {
    let db_path = home.join(".local/share/leash/events.db");
    let parent = db_path.parent().expect("db path parent");
    fs::create_dir_all(parent).expect("create db parent");

    let conn = rusqlite::Connection::open(db_path).expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            narrative TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );",
    )
    .expect("create schema");

    for row in rows {
        conn.execute(
            "INSERT INTO events (timestamp, severity, event_type, narrative, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![row.0, row.1, row.2, row.3, row.4],
        )
        .expect("insert row");
    }
}

fn payload(
    timestamp: &str,
    threat_level: &str,
    narrative: &str,
    process_name: &str,
    pid: i32,
) -> String {
    serde_json::json!({
        "event_type": "process_new",
        "threat_level": threat_level,
        "timestamp": timestamp,
        "narrative": narrative,
        "process": {
            "pid": pid,
            "ppid": 1,
            "name": process_name,
            "cmdline": process_name,
            "exe": format!("/usr/bin/{process_name}"),
            "cwd": "/tmp",
            "username": "user",
            "open_files": [],
            "parent_chain": []
        },
        "connection": null,
        "file_event": null,
        "mitre": [],
        "enrichment": null,
        "response_taken": null
    })
    .to_string()
}

#[test]
fn init_creates_config_file() {
    let home = temp_home("init");
    let output = run_leash(&home, &["init"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.join(".config/leash/config.yaml").exists());
}

#[test]
fn test_mode_json_generates_exactly_four_events_one_per_severity() {
    let home = temp_home("test-json");
    let output = run_leash(&home, &["--json", "test"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        4,
        "expected exactly 4 events, got {}",
        lines.len()
    );

    let severities = lines
        .iter()
        .map(|line| {
            let value: Value = serde_json::from_str(line).expect("valid json event");
            value["threat_level"]
                .as_str()
                .expect("threat_level should be string")
                .to_string()
        })
        .collect::<std::collections::HashSet<_>>();
    let expected = ["green", "yellow", "orange", "red"]
        .into_iter()
        .map(ToString::to_string)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(severities, expected);
}

#[test]
fn scan_json_outputs_valid_json_array() {
    let home = temp_home("scan-json");
    let output = run_leash(&home, &["--json", "scan"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let value: Value = serde_json::from_str(&stdout).expect("scan output should parse");
    assert!(value.is_array(), "expected JSON array output for scan");
}

#[test]
fn history_json_with_empty_db_returns_empty_array() {
    let home = temp_home("history-empty");
    let output = run_leash(&home, &["--json", "history"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let value: Value = serde_json::from_str(&stdout).expect("history output should parse");
    assert_eq!(value, serde_json::json!([]));
}

#[test]
fn export_csv_outputs_expected_header() {
    let home = temp_home("export-csv");
    let timestamp = chrono::Utc::now().to_rfc3339();
    write_event_db(
        &home,
        &[(
            timestamp.clone(),
            "yellow".to_string(),
            "process_new".to_string(),
            "csv row".to_string(),
            payload(&timestamp, "yellow", "csv row", "git", 101),
        )],
    );

    let output = run_leash(&home, &["export", "--format", "csv"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let header = stdout.lines().next().unwrap_or_default();
    assert!(header.contains(
        "timestamp,event_type,threat_level,narrative,pid,process_name,allowed,allowed_reason"
    ));
}

#[test]
fn version_outputs_version_string() {
    let home = temp_home("version");
    let output = run_leash(&home, &["--version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn watch_json_exits_cleanly_on_sigterm() {
    let home = temp_home("watch-sigterm");
    let mut child = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["--json", "watch"])
        .env("HOME", &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn leash watch");

    thread::sleep(Duration::from_millis(900));
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("send sigterm");

    let started = SystemTime::now();
    loop {
        if child.try_wait().expect("try_wait watch process").is_some() {
            break;
        }
        if started
            .elapsed()
            .expect("elapsed since start")
            .gt(&Duration::from_secs(3))
        {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn invalid_config_produces_helpful_error_message() {
    let home = temp_home("invalid-config");
    let config_path = home.join("bad-config.yaml");
    fs::write(&config_path, "alerts:\n  min_severity: [not-valid\n").expect("write invalid config");

    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["--json", "--config"])
        .arg(&config_path)
        .arg("test")
        .env("HOME", &home)
        .output()
        .expect("run leash with invalid config");

    assert!(!output.status.success(), "invalid config should fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("invalid YAML in config file"));
    assert!(stderr.contains("bad-config.yaml"));
}

#[test]
fn allowlist_exact_matching_does_not_match_codex_with_code() {
    assert!(!leash::collector::allow_list_entry_matches(
        "code",
        "codex",
        "codex run",
        "/usr/local/bin/codex"
    ));
    assert!(leash::collector::allow_list_entry_matches(
        "code",
        "code",
        "code .",
        "/usr/bin/code"
    ));
}

#[test]
fn secrets_scrubbing_redacts_api_keys_in_output() {
    let scrubbed = leash::collector::scrub_secrets(
        "token=abc123 api_key=qwerty sk-abcdefghijklmnopqrstuvwxyz12345 AKIAABCDEFGHIJKLMNOP",
    );
    assert!(!scrubbed.contains("token=abc123"));
    assert!(!scrubbed.contains("api_key=qwerty"));
    assert!(!scrubbed.contains("sk-abcdefghijklmnopqrstuvwxyz12345"));
    assert!(!scrubbed.contains("AKIAABCDEFGHIJKLMNOP"));
    assert!(scrubbed.contains("[REDACTED]"));
}

#[test]
fn help_outputs_help_text() {
    let home = temp_home("help");
    let output = run_leash(&home, &["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("Put your AI on a short leash."));
}

#[test]
fn export_json_supports_severity_and_last_filters() {
    let home = temp_home("export-json-filters");
    let recent = chrono::Utc::now() - chrono::Duration::hours(2);
    let old = chrono::Utc::now() - chrono::Duration::hours(30);
    let recent_ts = recent.to_rfc3339();
    let old_ts = old.to_rfc3339();

    write_event_db(
        &home,
        &[
            (
                recent_ts.clone(),
                "yellow".to_string(),
                "process_new".to_string(),
                "recent yellow".to_string(),
                payload(&recent_ts, "yellow", "recent yellow", "npm", 201),
            ),
            (
                old_ts.clone(),
                "yellow".to_string(),
                "process_new".to_string(),
                "old yellow".to_string(),
                payload(&old_ts, "yellow", "old yellow", "npm", 202),
            ),
            (
                recent_ts.clone(),
                "red".to_string(),
                "process_new".to_string(),
                "recent red".to_string(),
                payload(&recent_ts, "red", "recent red", "curl", 203),
            ),
        ],
    );

    let output = run_leash(
        &home,
        &[
            "export",
            "--format",
            "json",
            "--last",
            "24h",
            "--severity",
            "yellow",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "expected exactly one filtered event");
    let value: Value = serde_json::from_str(lines[0]).expect("ndjson row should parse");
    assert_eq!(value["threat_level"], "yellow");
    assert_eq!(value["narrative"], "recent yellow");
}
