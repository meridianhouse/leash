#![deny(clippy::all)]

mod alerts;
mod app;
mod cli;
mod collector;
mod config;
mod datasets;
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

use crate::app::{
    init_config, init_tracing, print_status, run_agent, run_test_alerts, stop_agent,
    update_datasets,
};
use crate::cli::{AuthCommand, Cli, Commands};
use crate::config::Config;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), app::DynError> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => init_config(cli.json).await?,
        Commands::Update => update_datasets(cli.config.as_deref(), cli.json).await?,
        Commands::Start => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, false, cli.json, cli.dry_run, cli.ebpf).await?;
        }
        Commands::Watch => {
            let cfg = Config::load(cli.config.as_deref())?;
            run_agent(cfg, true, cli.json, cli.dry_run, cli.ebpf).await?;
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
        Commands::Stop => stop_agent(cli.config.as_deref(), cli.json)?,
        Commands::Auth { command } => match command {
            AuthCommand::SetPassword => {
                let mut password = String::new();
                std::io::stdin().read_line(&mut password)?;
                let trimmed = password.trim_end_matches(['\r', '\n']);
                let hash = blake3::hash(trimmed.as_bytes());
                println!("{}", hash.to_hex());
            }
        },
    }

    Ok(())
}
