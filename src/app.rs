use crate::alerts::AlertDispatcher;
use crate::collector::ProcessCollector;
use crate::config::Config;
use crate::display::render_watch_ui;
use crate::egress::EgressMonitor;
use crate::fim::FileIntegrityMonitor;
use crate::history;
use crate::models::SecurityEvent;
use crate::response::ResponseEngine;
use crate::test_events::build_test_events;
use crate::watchdog::Watchdog;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nu_ansi_term::Color;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;
use tokio::time::{Duration, interval, sleep};
use tracing::{debug, error, info, warn};

const PID_FILE: &str = "/tmp/leash.pid";

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "leash=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

pub async fn run_agent(cfg: Config, watch_mode: bool, json_output: bool) -> Result<(), DynError> {
    ensure_single_instance()?;
    write_pid_file()?;

    if !json_output {
        print_startup_banner();
    }

    let (event_tx, _) = broadcast::channel::<SecurityEvent>(8_192);
    let collector = ProcessCollector::new(cfg.clone(), event_tx.clone());
    let egress = EgressMonitor::new(cfg.clone(), event_tx.clone());
    let fim = FileIntegrityMonitor::new(cfg.clone(), event_tx.clone())?;
    let alerts = AlertDispatcher::new(cfg.clone(), event_tx.subscribe())?;
    let response = ResponseEngine::new(cfg.clone(), event_tx.subscribe());
    let watchdog = Watchdog::new(cfg.clone(), event_tx.clone());
    let history_tx = event_tx.clone();
    let history_handle =
        tokio::spawn(async move { history::record_events(history_tx.subscribe()).await });

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
    tokio::signal::ctrl_c().await?;
    info!("Shutdown requested.");

    collector_handle.abort();
    egress_handle.abort();
    fim_handle.abort();
    alerts_handle.abort();
    response_handle.abort();
    watchdog_handle.abort();
    history_handle.abort();
    if let Some(handle) = watch_handle {
        handle.abort();
    }

    cleanup_pid_file();
    Ok(())
}

pub async fn run_test_alerts(cfg: Config, json_output: bool) -> Result<(), DynError> {
    let (event_tx, _) = broadcast::channel::<SecurityEvent>(64);
    let alerts = AlertDispatcher::new(cfg, event_tx.subscribe())?;
    let history_tx = event_tx.clone();
    let history_handle =
        tokio::spawn(async move { history::record_events(history_tx.subscribe()).await });
    let alerts_handle = tokio::spawn(async move { alerts.run().await });

    let started_at = chrono::Utc::now();
    let mut recent_events: VecDeque<SecurityEvent> = VecDeque::with_capacity(20);

    for event in build_test_events() {
        let _ = event_tx.send(event.clone());

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
    let running = if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            Path::new(&format!("/proc/{pid}")).exists()
        } else {
            false
        }
    } else {
        false
    };

    if json_output {
        let value = serde_json::json!({
            "name": "Leash",
            "running": running,
            "pid_file": PID_FILE,
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if running {
        println!("{}", Color::Green.paint("Leash is running"));
    } else {
        println!("{}", Color::Red.paint("Leash is stopped"));
    }

    Ok(())
}

pub fn stop_agent(json_output: bool) -> Result<(), DynError> {
    let pid_str = fs::read_to_string(PID_FILE)?;
    let pid = pid_str.trim().parse::<i32>()?;
    signal::kill(Pid::from_raw(pid), Signal::SIGTERM)?;
    cleanup_pid_file();

    if json_output {
        let value = serde_json::json!({
            "stopped": true,
            "pid": pid,
            "timestamp": chrono::Utc::now(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Sent SIGTERM to Leash (PID {pid})");
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
    if let Ok(pid_str) = fs::read_to_string(PID_FILE)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
    {
        let proc_path = PathBuf::from(format!("/proc/{pid}"));
        if proc_path.exists() {
            return Err(format!("Leash already running with PID {pid}").into());
        }
    }
    Ok(())
}

fn write_pid_file() -> Result<(), DynError> {
    fs::write(PID_FILE, format!("{}\n", std::process::id()))?;
    Ok(())
}

fn cleanup_pid_file() {
    if let Err(err) = fs::remove_file(PID_FILE) {
        debug!(?err, "failed to remove pid file");
    }
}
