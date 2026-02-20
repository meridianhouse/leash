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

    #[arg(
        long,
        global = true,
        help = "Detect events but do not send alerts; print would-be alerts to stdout"
    )]
    pub dry_run: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Initialize ~/.config/leash/config.yaml from template")]
    Init,
    #[command(
        about = "Force refresh LOLRMM + LOLDrivers + GTFOBins + LOT Tunnels + LOLC2 datasets"
    )]
    Update,
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
    #[command(about = "Export stored history events")]
    Export {
        #[arg(long, default_value = "json", value_parser = ["json", "csv"])]
        format: String,
        #[arg(long, help = "Time window to query (supported: 1h, 24h)")]
        last: Option<String>,
        #[arg(long, help = "Filter by severity (green, yellow, orange, red)")]
        severity: Option<String>,
    },
    #[command(about = "Stop Leash daemon")]
    Stop,
    #[command(about = "Authentication helper commands")]
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    #[command(about = "Read a password from stdin and print its blake3 hash")]
    SetPassword,
}
