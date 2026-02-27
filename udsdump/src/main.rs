mod capture;
mod display;
mod filter;
mod list;
mod stats;
mod top;

use clap::{Parser, Subcommand, ValueEnum};
use nix::unistd::Uid;

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

/// Check if running as root or with required capabilities.
fn check_permissions(command: &str) -> anyhow::Result<()> {
    if command == "list" {
        return Ok(());
    }

    if !Uid::effective().is_root() {
        anyhow::bail!(
            "udsdump {} requires root privileges or CAP_BPF + CAP_PERFMON capabilities.\n\
             Try: sudo udsdump {}",
            command,
            command
        );
    }
    Ok(())
}

/// Check minimum kernel version for eBPF support.
fn check_kernel_version() -> anyhow::Result<()> {
    let uname = nix::sys::utsname::uname()?;
    let release = uname.release().to_string_lossy();
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() >= 2 {
        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        if major < 5 || (major == 5 && minor < 4) {
            anyhow::bail!(
                "udsdump requires Linux kernel >= 5.4 for BTF/CO-RE support.\n\
                 Current kernel: {}",
                release
            );
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let cmd_name = match &cli.command {
        Commands::Capture(_) => "capture",
        Commands::List(_) => "list",
        Commands::Stats(_) => "stats",
        Commands::Top(_) => "top",
    };

    check_permissions(cmd_name)?;

    if cmd_name != "list" && cmd_name != "stats" {
        check_kernel_version()?;
    }

    match cli.command {
        Commands::Capture(args) => capture::run(args),
        Commands::List(args) => list::run(args),
        Commands::Stats(args) => stats::run(args),
        Commands::Top(args) => top::run(args),
    }
}
