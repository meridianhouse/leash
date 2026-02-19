#![deny(clippy::all)]

mod alerts;
mod app;
mod cli;
mod collector;
mod config;
mod display;
mod ebpf;
mod egress;
mod fim;
mod history;
mod mitre;
mod models;
mod response;
mod scan;
mod test_events;
mod watchdog;

use crate::app::{init_config, init_tracing, print_status, run_agent, run_test_alerts, stop_agent};
use crate::cli::{Cli, Commands};
use crate::config::Config;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), app::DynError> {
    init_tracing();
    let cli = Cli::parse();
    if cli.ebpf {
        println!("eBPF coming in v0.2");
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
        Commands::Stop => stop_agent(cli.json)?,
    }

    Ok(())
}
