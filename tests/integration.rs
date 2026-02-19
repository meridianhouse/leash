use serde_json::Value;
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
