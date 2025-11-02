
use std::path::PathBuf;
use clap::{Parser, Subcommand, Args};
use chrono::{DateTime, Utc};
use crate::commands::parse::execute_parse;
use crate::commands::watch::execute_watch;

#[derive(Parser)]
#[command(name = "Sysmon Log Analyzer")]
#[command(version = "0.1.0")]
#[command(author = "Serhii Smoliak")]
#[command(about = "Windows Sysmon log analysis tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Parse .evtx file
    Parse(ParseCommand),

    /// Real-time monitoring of the live Sysmon channel (Windows only)
    #[cfg(windows)]
    Watch(WatchCommand),
}

#[derive(Args)]
pub struct ParseCommand {
    /// Path to .evtx file
    #[arg(value_name = "FILE")]
    pub file_path: PathBuf,

    /// Display events whose Event ID is in the provided list (e.g. 1,2,7)
    #[arg(long, value_delimiter = ',')]
    pub event_id: Option<Vec<u8>>,

    /// Search by substring in key fields
    #[arg(long)]
    pub search: Option<String>,

    /// Include events after this time (format: YYYY-MM-DD HH:MM:SS)
    #[arg(long)]
    pub after: Option<DateTime<Utc>>,

    /// Include events before this time (format: YYYY-MM-DD HH:MM:SS)
    #[arg(long)]
    pub before: Option<DateTime<Utc>>,

    /// Enable anomaly detection
    #[arg(long, short)]
    pub detect: bool,
}

#[cfg(windows)]
#[derive(Args)]
pub struct WatchCommand {
    /// Display events whose Event ID is in the provided list (e.g. 1,2,7)
    #[arg(long, value_delimiter = ',')]
    pub event_id: Option<Vec<u8>>,

    /// Search by substring in key fields
    #[arg(long)]
    pub search: Option<String>,

    /// Enable anomaly detection
    #[arg(long, short)]
    pub detect: bool,
}

pub fn execute(config: Config) -> anyhow::Result<()> {
    match config.command {
        Commands::Parse(cmd) => {
            execute_parse(cmd)
        }
        #[cfg(windows)]
        Commands::Watch(cmd) => {
            execute_watch(cmd)
        }
    }
}
pub fn parse_args() -> Config {
    Config {
        command: Cli::parse().command
    }
}
pub struct Config {
    pub command: Commands,
}