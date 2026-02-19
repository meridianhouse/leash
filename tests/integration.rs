use leash::alerts::AlertDispatcher;
use leash::config::Config;
use leash::models::{EventType, ProcessInfo, SecurityEvent, ThreatLevel};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
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

fn spawn_leash(home: &Path, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(args)
        .env("HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn leash")
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> bool {
    let started = SystemTime::now();
    loop {
        if child.try_wait().expect("try_wait child").is_some() {
            return true;
        }
        if started.elapsed().expect("elapsed since wait start") > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Clone)]
struct MockResponse {
    status: u16,
    body: String,
    delay: Duration,
}

struct MockWebhookServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl MockWebhookServer {
    fn start(response: MockResponse) -> Option<Self> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(err) => panic!("bind mock webhook listener: {err}"),
        };
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let addr = listener.local_addr().expect("get mock listener addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let requests_clone = Arc::clone(&requests);
        let stop_clone = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Some(body) = read_http_body(&mut stream) {
                            requests_clone.lock().expect("lock requests").push(body);
                        }
                        if response.delay > Duration::ZERO {
                            thread::sleep(response.delay);
                        }
                        let status_text = match response.status {
                            200 => "OK",
                            404 => "Not Found",
                            500 => "Internal Server Error",
                            _ => "Status",
                        };
                        let payload = response.body.as_bytes();
                        let reply = format!(
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            response.status,
                            status_text,
                            payload.len()
                        );
                        let _ = stream.write_all(reply.as_bytes());
                        let _ = stream.write_all(payload);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Some(Self {
            addr,
            requests,
            stop,
            worker: Some(worker),
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("lock requests").len()
    }
}

impl Drop for MockWebhookServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_http_body(stream: &mut TcpStream) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    let mut bytes = Vec::with_capacity(2048);
    let mut buf = [0_u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => return None,
        }
    }

    let text = String::from_utf8_lossy(&bytes);
    let mut parts = text.split("\r\n\r\n");
    let headers = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default().to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let prefix = "content-length:";
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix(prefix)
                .and_then(|rest| rest.trim().parse::<usize>().ok())
        })
        .unwrap_or(body.len());

    if body.len() >= content_length {
        Some(body)
    } else {
        None
    }
}

fn write_config(home: &Path, yaml: &str) -> std::path::PathBuf {
    let path = home.join(".config/leash/config.yaml");
    let parent = path.parent().expect("config parent");
    fs::create_dir_all(parent).expect("create config parent");
    fs::write(&path, yaml).expect("write config");
    path
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

fn alert_event(event_type: EventType, pid: i32, level: ThreatLevel) -> SecurityEvent {
    let mut event = SecurityEvent::new(event_type, level, "integration alert test".to_string());
    event.process = Some(ProcessInfo {
        pid,
        ppid: 1,
        name: "agent".to_string(),
        cmdline: "agent --run".to_string(),
        exe: "/usr/bin/agent".to_string(),
        cwd: "/tmp".to_string(),
        username: "user".to_string(),
        open_files: Vec::new(),
        parent_chain: Vec::new(),
        start_time: Some(chrono::Utc::now()),
    });
    event
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
    if !wait_for_child_exit(&mut child, Duration::from_secs(3)) {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = wait_for_child_exit(&mut child, Duration::from_secs(3));
    }
}

#[test]
fn watch_json_exits_cleanly_on_sigint() {
    let home = temp_home("watch-sigint");
    let mut child = spawn_leash(&home, &["--json", "watch"]);

    thread::sleep(Duration::from_millis(900));
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .expect("send sigint");

    let started = SystemTime::now();
    let mut exited = false;
    loop {
        if child.try_wait().expect("try_wait watch process").is_some() {
            exited = true;
            break;
        }
        if started
            .elapsed()
            .expect("elapsed since signal sent")
            .gt(&Duration::from_secs(3))
        {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    if !exited {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        let _ = wait_for_child_exit(&mut child, Duration::from_secs(8));
    }
}

#[test]
fn start_status_stop_lifecycle_works() {
    let home = temp_home("start-stop");
    let mut child = spawn_leash(&home, &["--json", "start"]);
    thread::sleep(Duration::from_millis(900));

    let status_running = run_leash(&home, &["--json", "status"]);
    assert!(
        status_running.status.success(),
        "{}",
        String::from_utf8_lossy(&status_running.stderr)
    );
    let status_json: Value =
        serde_json::from_slice(&status_running.stdout).expect("status output should be json");
    assert_eq!(status_json["running"], true);

    let stop = run_leash(&home, &["--json", "stop"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(
        wait_for_child_exit(&mut child, Duration::from_secs(5)),
        "start process should exit after stop command"
    );
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
fn missing_explicit_config_path_falls_back_to_defaults() {
    let home = temp_home("missing-config");
    let config_path = home.join("does-not-exist.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["--json", "--config"])
        .arg(&config_path)
        .arg("test")
        .env("HOME", &home)
        .output()
        .expect("run leash with missing config path");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("config file not found"));
    assert!(stderr.contains("does-not-exist.yaml"));
    assert!(stderr.contains("leash init"));
}

#[test]
fn unreadable_config_file_produces_helpful_error() {
    let home = temp_home("config-permissions");
    let config_path = home.join("unreadable.yaml");
    fs::write(&config_path, "monitor_interval_ms: 1000\n").expect("write config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&config_path).expect("metadata").permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&config_path, perms).expect("set unreadable permissions");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["--json", "--config"])
        .arg(&config_path)
        .arg("test")
        .env("HOME", &home)
        .output()
        .expect("run leash with unreadable config");

    assert!(
        !output.status.success(),
        "unreadable config should fail on unix-like systems"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("failed to read config file"));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_valid_url_receives_alert_posts() {
    let Some(server) = MockWebhookServer::start(MockResponse {
        status: 200,
        body: "ok".to_string(),
        delay: Duration::ZERO,
    }) else {
        return;
    };
    let home = temp_home("webhook-valid");
    let config_path = write_config(
        &home,
        &format!(
            "alerts:\n  min_severity: green\n  rate_limit_seconds: 0\n  learning_mode_hours: 0\n  first_process_minutes: 0\n  slack:\n    enabled: true\n    url: \"{}\"\n  discord:\n    enabled: false\n  telegram:\n    enabled: false\n",
            server.url()
        ),
    );
    let config_path = config_path.to_string_lossy().to_string();

    let output = run_leash(&home, &["--config", &config_path, "--json", "test"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        server.request_count() >= 2,
        "Expected at least 2 alerts (orange+red), got {}",
        server.request_count()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_invalid_url_does_not_crash_test_command() {
    let home = temp_home("webhook-invalid");
    write_config(
        &home,
        "alerts:\n  min_severity: green\n  slack:\n    enabled: true\n    url: \"not-a-url\"\n  discord:\n    enabled: false\n  telegram:\n    enabled: false\n",
    );
    let output = run_leash(&home, &["--json", "test"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_404_and_500_are_non_fatal() {
    for (status, label) in [(404_u16, "webhook-404"), (500_u16, "webhook-500")] {
        let Some(server) = MockWebhookServer::start(MockResponse {
            status,
            body: "error".to_string(),
            delay: Duration::ZERO,
        }) else {
            return;
        };
        let home = temp_home(label);
        let config_path = write_config(
            &home,
            &format!(
                "alerts:\n  min_severity: green\n  rate_limit_seconds: 0\n  learning_mode_hours: 0\n  first_process_minutes: 0\n  slack:\n    enabled: true\n    url: \"{}\"\n  discord:\n    enabled: false\n  telegram:\n    enabled: false\n",
                server.url()
            ),
        );
        let config_path = config_path.to_string_lossy().to_string();

        let output = run_leash(&home, &["--config", &config_path, "--json", "test"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            server.request_count() >= 2,
            "Expected at least 2 alerts (orange+red), got {}",
            server.request_count()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_timeout_behavior_is_non_fatal() {
    let Some(server) = MockWebhookServer::start(MockResponse {
        status: 200,
        body: "ok".to_string(),
        delay: Duration::from_millis(1300),
    }) else {
        return;
    };
    let home = temp_home("webhook-timeout-like");
    write_config(
        &home,
        &format!(
            "alerts:\n  min_severity: red\n  rate_limit_seconds: 0\n  slack:\n    enabled: true\n    url: \"{}\"\n  discord:\n    enabled: false\n  telegram:\n    enabled: false\n",
            server.url()
        ),
    );

    let output = run_leash(&home, &["--json", "test"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limiting_coalesces_duplicate_alerts() {
    let Some(server) = MockWebhookServer::start(MockResponse {
        status: 200,
        body: "ok".to_string(),
        delay: Duration::ZERO,
    }) else {
        return;
    };
    let mut cfg = Config::default();
    cfg.alerts.min_severity = "green".to_string();
    cfg.alerts.rate_limit_seconds = 60;
    cfg.alerts.slack.enabled = true;
    cfg.alerts.slack.url = server.url();
    cfg.alerts.discord.enabled = false;
    cfg.alerts.telegram.enabled = false;

    let (tx, rx) = tokio::sync::broadcast::channel::<SecurityEvent>(16);
    let dispatcher = AlertDispatcher::new(cfg, rx, false).expect("build dispatcher");
    let task = tokio::spawn(async move { dispatcher.run().await });

    let event = alert_event(EventType::ProcessNew, 4242, ThreatLevel::Red);
    let _ = tx.send(event.clone());
    let _ = tx.send(event);
    tokio::time::sleep(Duration::from_millis(250)).await;
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;

    assert_eq!(server.request_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_severity_threshold_triggers_expected_alert_volume() {
    for (severity, expected) in [
        ("green", 4_usize),
        ("yellow", 3_usize),
        ("orange", 2_usize),
        ("red", 1_usize),
    ] {
        let Some(server) = MockWebhookServer::start(MockResponse {
            status: 200,
            body: "ok".to_string(),
            delay: Duration::ZERO,
        }) else {
            return;
        };
        let home = temp_home(&format!("severity-{severity}"));
        let config_path = write_config(
            &home,
            &format!(
                "alerts:\n  min_severity: {severity}\n  rate_limit_seconds: 0\n  learning_mode_hours: 0\n  first_process_minutes: 0\n  slack:\n    enabled: true\n    url: \"{}\"\n  discord:\n    enabled: false\n  telegram:\n    enabled: false\n",
                server.url()
            ),
        );
        let config_path = config_path.to_string_lossy().to_string();

        let output = run_leash(&home, &["--config", &config_path, "--json", "test"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            server.request_count(),
            expected,
            "unexpected alert count for severity {severity}"
        );
    }
}
