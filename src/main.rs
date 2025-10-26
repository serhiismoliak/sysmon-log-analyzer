mod telemetry;
mod cli;

use anyhow::Result;

fn main() {
    telemetry::init_tracing();
    tracing::info!("Staring Sysmon Log Analyzer");
    let config = cli::parse_args();
    cli::execute(config);
}
