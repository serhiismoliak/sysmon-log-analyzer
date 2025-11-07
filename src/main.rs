use anyhow::Result;
use security_log_analyser::{cli, telemetry};

fn main() -> Result<()> {
    telemetry::init_tracing();
    tracing::info!("Staring Sysmon Log Analyzer");
    let config = cli::parse_args();
    cli::execute(config)
}
