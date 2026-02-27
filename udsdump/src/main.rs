mod capture;
mod display;
mod filter;
mod list;
mod stats;
mod top;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "udsdump",
    version,
    about = "Unix Domain Socket packet capture and analysis tool"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Capture UDS traffic in real-time
    Capture(CaptureArgs),
    /// List current UDS connections
    List(ListArgs),
    /// Show UDS statistics
    Stats(StatsArgs),
    /// Real-time sorted traffic view
    Top(TopArgs),
}

#[derive(Parser)]
pub struct CaptureArgs {
    /// Filter by socket path (prefix match)
    #[arg(long)]
    pub path: Option<String>,

    /// Filter by process PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Filter by process name
    #[arg(long)]
    pub comm: Option<String>,

    /// Filter by socket type
    #[arg(long, value_enum)]
    pub r#type: Option<SocketTypeFilter>,

    /// Display payload as hex dump
    #[arg(long)]
    pub hex: bool,

    /// Display payload as ASCII (default)
    #[arg(long)]
    pub ascii: bool,

    /// Maximum payload bytes to display per packet
    #[arg(long, default_value = "256")]
    pub max_bytes: usize,

    /// Stop after capturing N packets
    #[arg(long)]
    pub count: Option<u64>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct ListArgs {
    /// Filter by socket path
    #[arg(long)]
    pub path: Option<String>,

    /// Filter by process PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Filter by connection state
    #[arg(long)]
    pub state: Option<String>,

    /// Filter by socket type
    #[arg(long, value_enum)]
    pub r#type: Option<SocketTypeFilter>,

    /// Resolve inode to process information
    #[arg(long)]
    pub resolve: bool,
}

#[derive(Parser)]
pub struct StatsArgs {
    /// Filter by socket path
    #[arg(long)]
    pub path: Option<String>,

    /// Filter by process PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Refresh interval in seconds (0 = single snapshot)
    #[arg(long, default_value = "0")]
    pub interval: u64,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct TopArgs {
    /// Sort field
    #[arg(long, value_enum, default_value = "bytes")]
    pub sort: SortField,

    /// Refresh interval in seconds
    #[arg(long, default_value = "1")]
    pub interval: u64,
}

#[derive(Clone, ValueEnum)]
pub enum SocketTypeFilter {
    Stream,
    Dgram,
}

#[derive(Clone, ValueEnum)]
pub enum SortField {
    Bytes,
    Msgs,
    Rate,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture(args) => capture::run(args),
        Commands::List(args) => list::run(args),
        Commands::Stats(args) => stats::run(args),
        Commands::Top(args) => top::run(args),
    }
}
