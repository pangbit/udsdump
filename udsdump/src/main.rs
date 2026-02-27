use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "udsdump", about = "Unix Domain Socket packet capture and analysis tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture UDS traffic in real-time
    Capture,
    /// List current UDS connections
    List,
    /// Show UDS statistics
    Stats,
    /// Real-time sorted traffic view
    Top,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Capture => println!("capture: not implemented"),
        Commands::List => println!("list: not implemented"),
        Commands::Stats => println!("stats: not implemented"),
        Commands::Top => println!("top: not implemented"),
    }
    Ok(())
}
