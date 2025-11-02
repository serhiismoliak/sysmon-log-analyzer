use crate::cli::WatchCommand;
use crate::sysmon::Event as SysmonEvent;
use crate::{filters, live_monitor};
use anyhow::Result;
use colored::Colorize;

#[cfg(windows)]
pub(crate) fn execute_watch(cmd: WatchCommand) -> Result<()> {
    let WatchCommand {
        event_id,
        search,
        detect,
    } = cmd;
    println!(
        "{}",
        "=== Security Log Analyzer - Live Monitor ==="
            .bright_cyan()
            .bold()
    );
    println!("Monitoring Sysmon events in real-time...\n");
    println!("Press {} to exit\n", "Ctrl+C".bright_red());

    let filter = filters::EventFilter::new()
        .with_event_ids(event_id)
        .with_search_term(search);
    let _captured_events: Vec<SysmonEvent> = live_monitor::start_monitoring(filter, detect)?;
    Ok(())
}
