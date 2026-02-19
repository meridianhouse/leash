use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_mode_json_events_are_well_formed() {
    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["--json", "test"])
        .output()
        .expect("run leash --json test");

    assert!(
        output.status.success(),
        "leash test command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();

    assert!(
        lines.len() >= 4,
        "expected at least 4 JSON events, got {}",
        lines.len()
    );

    for line in lines {
        let value: Value = serde_json::from_str(line).expect("each event must be valid JSON");
        assert!(value.get("event_type").is_some());
        assert!(value.get("threat_level").is_some());
        assert!(value.get("timestamp").is_some());
        assert!(value.get("narrative").is_some());
    }
}

#[test]
fn version_outputs_version_string() {
    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .arg("--version")
        .output()
        .expect("run leash --version");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_outputs_help_text() {
    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .arg("--help")
        .output()
        .expect("run leash --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("Put your AI on a short leash."));
}

fn temp_home(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("leash-int-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp home");
    dir
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
fn export_csv_outputs_expected_columns() {
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

    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["export", "--format", "csv"])
        .env("HOME", &home)
        .output()
        .expect("run leash export --format csv");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(
        stdout
            .lines()
            .next()
            .unwrap_or_default()
            .contains("timestamp,event_type,threat_level,narrative,pid,process_name")
    );
    assert!(stdout.contains("csv row"));
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

    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args([
            "export",
            "--format",
            "json",
            "--last",
            "24h",
            "--severity",
            "yellow",
        ])
        .env("HOME", &home)
        .output()
        .expect("run filtered export");

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
