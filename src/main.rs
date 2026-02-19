mod alerts;
mod cli;
mod collector;
mod config;
mod egress;
mod fim;
mod mitre;
mod models;
mod response;
mod watchdog;

use crate::alerts::AlertDispatcher;
use crate::cli::{Cli, Commands};
use crate::collector::ProcessCollector;
use crate::config::Config;
use crate::egress::EgressMonitor;
use crate::fim::FileIntegrityMonitor;
use crate::models::{EventType, SecurityEvent, ThreatLevel};
use crate::response::ResponseEngine;
use crate::watchdog::Watchdog;
use clap::Parser;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nu_ansi_term::{AnsiString, Color, Style};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

const PID_FILE: &str = "/tmp/leash.pid";

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Start => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, false, cli.json).await?;
        }
        Commands::Watch => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, true, cli.json).await?;
        }
        Commands::Status => {
            print_status(cli.json)?;
        }
        Commands::Stop => {
            stop_agent(cli.json)?;
        }
    }

    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "leash=info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn run_agent(cfg: Config, watch_mode: bool, json_output: bool) -> Result<(), DynError> {
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

    let _ = collector_handle.abort();
    let _ = egress_handle.abort();
    let _ = fim_handle.abort();
    let _ = alerts_handle.abort();
    let _ = response_handle.abort();
    let _ = watchdog_handle.abort();
    if let Some(handle) = watch_handle {
        let _ = handle.abort();
    }

    cleanup_pid_file();
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

fn render_watch_ui(recent_events: &VecDeque<SecurityEvent>, started_at: chrono::DateTime<chrono::Utc>) {
    print!("\x1b[2J\x1b[H");
    let now = chrono::Local::now();
    let uptime = chrono::Utc::now() - started_at;
    println!(
        "{}  {}  uptime={}s",
        Style::new().bold().paint("LEASH WATCH"),
        now.format("%Y-%m-%d %H:%M:%S"),
        uptime.num_seconds()
    );
    println!("{}", "─".repeat(90));

    if recent_events.is_empty() {
        println!("No events yet. Waiting for telemetry...");
        return;
    }

    for event in recent_events.iter().take(12) {
        let level = color_for_level(event.threat_level);
        println!(
            "{} {} {}",
            level,
            Color::Cyan.paint(format!("[{}]", event.event_type)),
            event.narrative
        );
        println!("   time: {}", event.timestamp.with_timezone(&chrono::Local).format("%H:%M:%S"));
        if let Some(process) = &event.process {
            println!(
                "   proc: {} ({})  exe: {}",
                Style::new().bold().paint(process.name.clone()),
                process.pid,
                truncate(&process.exe, 50)
            );
            println!("   tree: {}", format_process_tree(process));
        }
        if let Some(file_event) = &event.file_event {
            println!("   path: {}", truncate(&file_event.path, 80));
        }
        if let Some(mitre) = &event.mitre {
            println!("   mitre: {} {}", mitre.technique_id, mitre.name);
        }
        println!("{}", Style::new().dimmed().paint("·".repeat(90)));
    }
}

fn color_for_level(level: ThreatLevel) -> AnsiString<'static> {
    match level {
        ThreatLevel::Green => Color::Green.bold().paint("GREEN"),
        ThreatLevel::Yellow => Color::Yellow.bold().paint("YELLOW"),
        ThreatLevel::Orange => Color::Fixed(208).bold().paint("ORANGE"),
        ThreatLevel::Red => Color::Red.bold().paint("RED"),
        ThreatLevel::Nuclear => Color::Purple.bold().paint("NUCLEAR"),
    }
}

fn format_process_tree(process: &crate::models::ProcessInfo) -> String {
    if process.parent_chain.is_empty() {
        return format!("{}({})", process.name, process.pid);
    }

    let mut parts = process.parent_chain.clone();
    parts.reverse();
    parts.push(format!("{}({})", process.name, process.pid));
    parts.join(" -> ")
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!("{}...", value.chars().take(max_len.saturating_sub(3)).collect::<String>())
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
    if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let proc_path = PathBuf::from(format!("/proc/{pid}"));
            if proc_path.exists() {
                return Err(format!("Leash already running with PID {pid}").into());
            }
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

fn print_status(json_output: bool) -> Result<(), DynError> {
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

fn stop_agent(json_output: bool) -> Result<(), DynError> {
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

#[allow(dead_code)]
fn _event_for_status(narrative: String) -> SecurityEvent {
    SecurityEvent::new(EventType::SelfTamper, ThreatLevel::Green, narrative)
}
