#![deny(clippy::all)]

mod alerts;
mod app;
mod cli;
mod collector;
mod config;
mod display;
mod ebpf;
mod egress;
mod export;
mod fim;
mod history;
mod mitre;
mod models;
mod prompt_injection;
mod response;
mod scan;
mod stats;
mod test_events;
mod watchdog;

use crate::app::{init_config, init_tracing, print_status, run_agent, run_test_alerts, stop_agent};
use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::ebpf::{EbpfMonitor, attach_kernel_monitor};
use crate::models::{EventType, SecurityEvent, ThreatLevel};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), app::DynError> {
    init_tracing();
    let cli = Cli::parse();
    if cli.ebpf {
        let mut monitor = EbpfMonitor;
        if let Err(err) = attach_kernel_monitor(&mut monitor) {
            eprintln!("{err}");
        }
        if let Err(err) = ebpf::KernelMonitor::on_event(
            &mut monitor,
            &SecurityEvent::new(
                EventType::ProcessNew,
                ThreatLevel::Green,
                "eBPF smoke event".to_string(),
            ),
        ) {
            eprintln!("{err}");
        }
        if let Err(err) = ebpf::KernelMonitor::detach(&mut monitor) {
            eprintln!("{err}");
        }
    }

    match cli.command {
        Commands::Init => init_config(cli.json)?,
        Commands::Start => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, false, cli.json).await?;
        }
        Commands::Watch => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, true, cli.json).await?;
        }
        Commands::Test => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_test_alerts(cfg, cli.json).await?;
        }
        Commands::Scan => {
            let cfg = Config::load(cli.config.as_deref())?;
            scan::run_scan(cfg, cli.json)?;
        }
        Commands::Status => print_status(cli.json)?,
        Commands::History { last, severity } => {
            history::print_history(last.as_deref(), severity.as_deref(), cli.json)?;
        }
        Commands::Export {
            format,
            last,
            severity,
        } => {
            let export_format = export::ExportFormat::parse(&format)?;
            export::export_events(export_format, last.as_deref(), severity.as_deref())?;
        }
        Commands::Stop => stop_agent(cli.json)?,
    }

    Ok(())
}
