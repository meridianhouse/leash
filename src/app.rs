use crate::alerts::AlertDispatcher;
use crate::collector::ProcessCollector;
use crate::config::Config;
use crate::display::render_watch_ui;
use crate::egress::EgressMonitor;
use crate::fim::FileIntegrityMonitor;
use crate::history;
use crate::mitre;
use crate::models::SecurityEvent;
use crate::models::{EventType, ThreatLevel};
use crate::response::ResponseEngine;
use crate::stats;
use crate::test_events::build_test_events;
use crate::watchdog::Watchdog;
use nix::libc;
use nu_ansi_term::Color;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::time::{Duration, interval, sleep};
use tracing::{debug, error, info, warn};

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "leash=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

pub async fn run_agent(
    cfg: Config,
    watch_mode: bool,
    json_output: bool,
    dry_run: bool,
) -> Result<(), DynError> {
    ensure_single_instance()?;
    write_pid_file()?;

    if !json_output {
        print_startup_banner();
    }

    let (event_tx, _) = broadcast::channel::<SecurityEvent>(8_192);
    let collector = ProcessCollector::new(cfg.clone(), event_tx.clone());
    let egress = EgressMonitor::new(cfg.clone(), event_tx.clone());
    let fim = FileIntegrityMonitor::new(cfg.clone(), event_tx.clone())?;
    let alerts = AlertDispatcher::new(cfg.clone(), event_tx.subscribe(), dry_run)?;
    let response = ResponseEngine::new(cfg.clone(), event_tx.subscribe());
    let watchdog = Watchdog::new(cfg.clone(), event_tx.clone());
    let max_history_mb = cfg.max_history_mb;
    let history_tx = event_tx.clone();
    let history_handle = tokio::spawn(async move {
        history::record_events(history_tx.subscribe(), max_history_mb).await
    });
    let stats_tx = event_tx.clone();
    let stats_handle = tokio::spawn(async move { stats::track_events(stats_tx.subscribe()).await });

    let watch_handle = if watch_mode {
        Some(tokio::spawn(watch_events(
            event_tx.subscribe(),
            json_output,
        )))
    } else {
        None
    };

    let collector_handle = tokio::spawn(async move { collector.run().await });
    let egress_handle = tokio::spawn(async move { egress.run().await });
    let fim_handle = tokio::spawn(async move { fim.run().await });
    let alerts_handle = tokio::spawn(async move { alerts.run().await });
    let response_handle = tokio::spawn(async move { response.run().await });
    let watchdog_handle = tokio::spawn(async move { watchdog.run().await });

    info!("Leash is running. Press Ctrl-C to stop.");
    wait_for_shutdown_signal(&cfg, &event_tx).await?;
    info!("Shutdown requested.");

    collector_handle.abort();
    egress_handle.abort();
    fim_handle.abort();
    alerts_handle.abort();
    response_handle.abort();
    watchdog_handle.abort();
    history_handle.abort();
    stats_handle.abort();
    if let Some(handle) = watch_handle {
        handle.abort();
    }

    cleanup_pid_file();
    Ok(())
}

async fn wait_for_shutdown_signal(
    cfg: &Config,
    event_tx: &broadcast::Sender<SecurityEvent>,
) -> Result<(), DynError> {
    #[cfg(unix)]
    {
        let expected_hash = cfg.auth.stop_password_hash.trim().to_string();
        let socket_path = shutdown_socket_path()?;
        let listener = bind_shutdown_socket(&socket_path)?;
        let _socket_guard = ShutdownSocketGuard {
            path: socket_path.clone(),
        };

        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

        loop {
            tokio::select! {
                _ = sigint.recv() => {
                    if expected_hash.is_empty() {
                        break;
                    }
                    emit_ignored_signal_event(event_tx, "SIGINT");
                }
                _ = sigterm.recv() => {
                    if expected_hash.is_empty() {
                        break;
                    }
                    emit_ignored_signal_event(event_tx, "SIGTERM");
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((mut stream, _addr)) => {
                            match handle_shutdown_auth_request(&mut stream, &expected_hash).await {
                                Ok(true) => break,
                                Ok(false) => {}
                                Err(err) => warn!(?err, "failed to process shutdown auth request"),
                            }
                        }
                        Err(err) => warn!(?err, "shutdown socket accept failed"),
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

#[cfg(unix)]
fn bind_shutdown_socket(path: &Path) -> Result<UnixListener, DynError> {
    if let Some(parent) = path.parent() {
        create_runtime_dir(parent)?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(unix)]
struct ShutdownSocketGuard {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for ShutdownSocketGuard {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            debug!(?err, "failed to remove shutdown socket");
        }
    }
}

#[cfg(unix)]
fn emit_ignored_signal_event(event_tx: &broadcast::Sender<SecurityEvent>, signal_name: &str) {
    let event = mitre::infer_and_tag(SecurityEvent::new(
        EventType::SelfTamper,
        ThreatLevel::Red,
        format!(
            "Ignored {signal_name}; authenticated shutdown is required while stop password is enabled"
        ),
    ));
    if let Err(err) = event_tx.send(event) {
        stats::record_dropped_event();
        warn!(
            event_type = %err.0.event_type,
            "dropping event: broadcast channel full or closed"
        );
    }
}

#[cfg(unix)]
async fn handle_shutdown_auth_request(
    stream: &mut UnixStream,
    expected_hash: &str,
) -> Result<bool, DynError> {
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).await?;
    let provided = String::from_utf8_lossy(&payload);
    let provided_hash = provided.trim_end_matches(['\r', '\n']);
    let authorized = provided_hash == expected_hash;
    if authorized {
        stream.write_all(b"OK\n").await?;
    } else {
        stream.write_all(b"ERR\n").await?;
    }
    let _ = stream.shutdown().await;
    Ok(authorized)
}

fn shutdown_socket_path() -> Result<PathBuf, DynError> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
    let home = home.trim();
    if home.is_empty() {
        return Err("HOME is empty".into());
    }
    Ok(PathBuf::from(home).join(".local/run/leash.sock"))
}

fn send_shutdown_auth_request(socket_path: &Path, hash: &str) -> Result<(), DynError> {
    let mut stream = StdUnixStream::connect(socket_path)?;
    stream.write_all(format!("{hash}\n").as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) == "OK" {
        return Ok(());
    }
    Err("stop authentication rejected".into())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid is thread-safe and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn ensure_socket_owner(path: &Path) -> Result<(), DynError> {
    let metadata = fs::metadata(path)?;
    if metadata.uid() != current_uid() {
        return Err(format!(
            "Shutdown socket {} is not owned by current user",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(unix)]
fn assert_socket_not_symlink(path: &Path) -> Result<(), DynError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(format!("Shutdown socket path is a symlink: {}", path.display()).into());
        }
    }
    Ok(())
}

pub async fn run_test_alerts(cfg: Config, json_output: bool) -> Result<(), DynError> {
    let (event_tx, _) = broadcast::channel::<SecurityEvent>(64);
    let max_history_mb = cfg.max_history_mb;
    let alerts = AlertDispatcher::new(cfg, event_tx.subscribe(), false)?;
    let history_tx = event_tx.clone();
    let history_handle = tokio::spawn(async move {
        history::record_events(history_tx.subscribe(), max_history_mb).await
    });
    let alerts_handle = tokio::spawn(async move { alerts.run().await });

    let started_at = chrono::Utc::now();
    let mut recent_events: VecDeque<SecurityEvent> = VecDeque::with_capacity(20);

    for event in build_test_events() {
        if let Err(err) = event_tx.send(event.clone()) {
            stats::record_dropped_event();
            warn!(
                event_type = %err.0.event_type,
                "dropping event: broadcast channel full or closed"
            );
        }

        if json_output {
            match serde_json::to_string(&event) {
                Ok(line) => println!("{line}"),
                Err(err) => error!(?err, "failed to serialize test event"),
            }
        } else {
            if recent_events.len() >= 20 {
                let _ = recent_events.pop_back();
            }
            recent_events.push_front(event);
            render_watch_ui(&recent_events, started_at);
        }

        sleep(Duration::from_millis(350)).await;
    }

    sleep(Duration::from_secs(2)).await;
    history_handle.abort();
    alerts_handle.abort();
    Ok(())
}

pub fn print_status(json_output: bool) -> Result<(), DynError> {
    let pid_file = pid_file_path()?;
    let running = matches!(read_pid_from_file(&pid_file), Ok(Some(_)));

    if json_output {
        let stats = stats::load_snapshot().ok().flatten();
        let value = serde_json::json!({
            "name": "Leash",
            "running": running,
            "pid_file": pid_file,
            "stats": stats,
            "dropped_events": stats::dropped_events(),
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if running {
        println!("{}", Color::Green.paint("Leash is running"));
        println!("dropped events: {}", stats::dropped_events());
        if let Ok(Some(snapshot)) = stats::load_snapshot() {
            println!("events/minute: {:.2}", snapshot.events_per_minute);
            println!("total events: {}", snapshot.total_events);
            if !snapshot.events_by_severity.is_empty() {
                let severity_stats = snapshot
                    .events_by_severity
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("by severity: {severity_stats}");
            }
            if !snapshot.events_by_type.is_empty() {
                let type_stats = snapshot
                    .events_by_type
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("by type: {type_stats}");
            }
        }
    } else {
        println!("{}", Color::Red.paint("Leash is stopped"));
    }

    Ok(())
}

pub fn stop_agent(config_path: Option<&Path>, json_output: bool) -> Result<(), DynError> {
    let cfg = Config::load(config_path)?;
    let pid_file = pid_file_path()?;
    let pid = read_pid_from_file(&pid_file)?
        .map(|record| record.pid)
        .ok_or_else(|| {
            format!(
                "Leash is not running (missing or stale PID file at {})",
                pid_file.display()
            )
        })?;

    let mut stop_hash = String::new();
    if !cfg.auth.stop_password_hash.trim().is_empty() {
        let mut password = String::new();
        std::io::stdin().read_line(&mut password)?;
        let trimmed = password.trim_end_matches(['\r', '\n']);
        stop_hash = blake3::hash(trimmed.as_bytes()).to_hex().to_string();
    }

    let socket_path = shutdown_socket_path()?;
    assert_socket_not_symlink(&socket_path)?;
    ensure_socket_owner(&socket_path)?;
    send_shutdown_auth_request(&socket_path, &stop_hash)?;
    cleanup_pid_file();

    if json_output {
        let value = serde_json::json!({
            "stopped": true,
            "pid": pid,
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Sent authenticated shutdown request to Leash (PID {pid})");
    }

    Ok(())
}

pub fn init_config(json_output: bool) -> Result<(), DynError> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
    let target = PathBuf::from(home).join(".config/leash/config.yaml");
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    let template = include_str!("../config/default.yaml");
    fs::write(&target, template)?;

    if json_output {
        let value = serde_json::json!({
            "initialized": true,
            "path": target,
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Initialized Leash config at {}", target.display());
    }

    Ok(())
}

async fn watch_events(mut rx: broadcast::Receiver<SecurityEvent>, json_output: bool) {
    let mut ticker = interval(Duration::from_millis(700));
    let mut recent_events: VecDeque<SecurityEvent> = VecDeque::with_capacity(20);
    let started_at = chrono::Utc::now();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !json_output {
                    render_watch_ui(&recent_events, started_at);
                } else {
                    debug!("watch loop heartbeat");
                }
            }
            msg = rx.recv() => {
                match msg {
                    Ok(event) => {
                        if json_output {
                            match serde_json::to_string(&event) {
                                Ok(line) => println!("{line}"),
                                Err(err) => error!(?err, "failed to serialize event"),
                            }
                        } else {
                            if recent_events.len() >= 20 {
                                let _ = recent_events.pop_back();
                            }
                            recent_events.push_front(event);
                            render_watch_ui(&recent_events, started_at);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(lagged = n, "watch subscriber lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

fn print_startup_banner() {
    println!(
        "{}",
        Color::Cyan.bold().paint(
            r#"
 _      _____    _    ____  _   _
| |    | ____|  / \  / ___|| | | |
| |    |  _|   / _ \ \___ \| |_| |
| |___ | |___ / ___ \ ___) |  _  |
|_____||_____/_/   \_\____/|_| |_|
"#
        )
    );
}

fn ensure_single_instance() -> Result<(), DynError> {
    let pid_file = pid_file_path()?;
    if let Some(record) = read_pid_from_file(&pid_file)? {
        let pid = record.pid;
        return Err(format!("Leash already running with PID {pid}").into());
    }

    // Clear stale PID files once ownership checks pass.
    if pid_file.exists() {
        fs::remove_file(pid_file)?;
    }

    Ok(())
}

fn write_pid_file() -> Result<(), DynError> {
    let pid_file = pid_file_path()?;
    if let Some(parent) = pid_file.parent() {
        create_runtime_dir(parent)?;
    }

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&pid_file)?;
    let pid = std::process::id() as i32;
    let start_ticks = read_proc_start_ticks(pid)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    file.write_all(format!("{pid} {start_ticks}\n").as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn cleanup_pid_file() {
    let Ok(pid_file) = pid_file_path() else {
        return;
    };

    if let Err(err) = fs::remove_file(pid_file) {
        debug!(?err, "failed to remove pid file");
    }
}

fn pid_file_path() -> Result<PathBuf, DynError> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
    let home = home.trim();
    if home.is_empty() {
        return Err("HOME is empty".into());
    }

    Ok(PathBuf::from(home).join(".local/run/leash.pid"))
}

fn create_runtime_dir(path: &Path) -> Result<(), DynError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct PidRecord {
    pid: i32,
    start_ticks: Option<u64>,
}

fn read_pid_from_file(path: &Path) -> Result<Option<PidRecord>, DynError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(format!("PID file is not a regular file: {}", path.display()).into());
    }

    let current_uid = current_uid();
    if metadata.uid() != current_uid {
        return Err(format!("PID file {} is not owned by current user", path.display()).into());
    }

    let mut pid_raw = String::new();
    file.read_to_string(&mut pid_raw)?;
    let Some(record) = parse_pid_record(pid_raw.trim()) else {
        return Ok(None);
    };
    let pid = record.pid;
    if pid <= 0 {
        return Ok(None);
    }

    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    if !proc_path.exists() {
        return Ok(None);
    }

    let proc_meta = fs::metadata(proc_path)?;
    if proc_meta.uid() != current_uid {
        return Err(format!("PID {pid} is not owned by current user").into());
    }

    // If start ticks are present, enforce process identity to prevent PID reuse confusion.
    if let Some(expected_ticks) = record.start_ticks {
        let Some(actual_ticks) = read_proc_start_ticks(pid) else {
            return Ok(None);
        };
        if actual_ticks != expected_ticks {
            return Ok(None);
        }
    }

    Ok(Some(record))
}

fn parse_pid_record(raw: &str) -> Option<PidRecord> {
    let mut parts = raw.split_whitespace();
    let pid = parts.next()?.parse::<i32>().ok()?;
    let start_ticks = parts
        .next()
        .filter(|value| *value != "-")
        .and_then(|value| value.parse::<u64>().ok());
    Some(PidRecord { pid, start_ticks })
}

fn read_proc_start_ticks(pid: i32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let tail = stat.get(close + 2..)?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let start_ticks_index = 19;
    fields.get(start_ticks_index)?.parse::<u64>().ok()
}
