use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "leash", version, about = "Put your AI on a short leash.")]
pub struct Cli {
    #[arg(long, global = true, help = "Path to config YAML")]
    pub config: Option<PathBuf>,

    #[arg(long, global = true, help = "Machine-readable JSON output")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Initialize ~/.config/leash/config.yaml from template")]
    Init,
    #[command(about = "Start Leash daemon")]
    Start,
    #[command(about = "Start and stream detected events")]
    Watch,
    #[command(about = "Show daemon status")]
    Status,
    #[command(about = "Stop Leash daemon")]
    Stop,
}
