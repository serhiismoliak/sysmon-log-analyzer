use crate::cli::ParseCommand;
use anyhow::Result;
use colored::*;
use tracing::info;
use crate::{analyzer, display, filters, parser};

pub fn execute_parse(cmd: ParseCommand) -> Result<()> {
    let ParseCommand {
        file_path,
        event_id,
        search,
        detect,
        after,
        before,
    } = cmd;
    println!("{}", "Security Log Analyzer".bright_cyan().bold());
    println!("Analyzing file: {}\n", file_path.to_string_lossy().bright_yellow());
    let events = parser::parse_evtx_file(&file_path)?;
    let filters = filters::EventFilter::new()
        .with_event_ids(event_id)
        .with_search_term(search)
        .with_time_range(after, before);
    let filtered_events = filters.apply(&events);
    println!(
        "Total events found: {} (filtered {})",
        events.len().to_string().bright_green(),
        filtered_events.len().to_string().bright_red()
    );
    let anomalies = if detect {
        info!("Running anomaly detection");
        let detected = analyzer::detect_anomalies(&filtered_events);
        if !detected.is_empty() {
            println!("Anomalies detected:");
            for anomaly in &detected {
                println!("{}: {}", anomaly.severity().to_string().bright_red(), anomaly.description());
            }
        }
        detected
    } else {
        Vec::new()
    };
    display::display_events(&filtered_events);
    Ok(())
}