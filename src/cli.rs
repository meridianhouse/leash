use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "leash", version, about = "Put your AI on a short leash.")]
pub struct Cli {
    #[arg(long, global = true, help = "Path to config YAML")]
    pub config: Option<PathBuf>,

    #[arg(long, global = true, help = "Machine-readable JSON output")]
    pub json: bool,

    #[arg(long, global = true, help = "Enable eBPF kernel monitoring (preview)")]
    pub ebpf: bool,

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
    #[command(about = "Send fake GREEN/YELLOW/ORANGE/RED events through alerts")]
    Test,
    #[command(about = "One-time snapshot of active AI agents, trees, network, and sensitive FDs")]
    Scan,
    #[command(about = "Show daemon status")]
    Status,
    #[command(about = "Show stored event history")]
    History {
        #[arg(long, help = "Time window to query (supported: 1h, 24h)")]
        last: Option<String>,
        #[arg(
            long,
            help = "Filter by severity (green, yellow, orange, red, nuclear)"
        )]
        severity: Option<String>,
    },
    #[command(about = "Stop Leash daemon")]
    Stop,
}
