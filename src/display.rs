use crate::analyzer::{Anomaly, Severity};
use crate::helpers::HasSystem;
use crate::sysmon::Event as SysmonEvent;
use colored::{Color, ColoredString, Colorize};
use prettytable::{Cell, Row, Table};

const EVENTS_DISPLAYED: usize = 100;

pub fn display_events(events: &[SysmonEvent]) {
    if events.is_empty() {
        println!("{}", "No events to found".yellow());
        return;
    }
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Timestamp").style_spec("Fb"),
        Cell::new("ID").style_spec("Fb"),
        Cell::new("Event Type").style_spec("Fb"),
        Cell::new("Process").style_spec("Fb"),
        Cell::new("Details").style_spec("Fb"),
    ]));
    for event in events.iter().take(EVENTS_DISPLAYED) {
        add_event_row(&mut table, event);
    }
    table.printstd();
    if events.len() > EVENTS_DISPLAYED {
        println!(
            "\n{} Showing first {} events out of {}",
            "\u{2139}".bright_blue(),
            EVENTS_DISPLAYED,
            events.len()
        );
    }
}

/// Add a single event row to the table
fn add_event_row(table: &mut Table, event: &SysmonEvent) {
    let (color, process_name) = get_process_and_color(event);
    let details = format_event_details(event);
    let event_type = event.name();
    table.add_row(Row::new(vec![
        Cell::new(&event.system().time_created.system_time),
        Cell::new(&event.system().event_id.event_id.to_string()),
        Cell::new(event_type),
        Cell::new(&*process_name.color(color)),
        Cell::new(details.as_str()),
    ]));
}
/// Display detected anomalies in batch mode
pub fn display_anomalies(anomalies: &[Anomaly]) {
    println!("{}", "🔍 Detected Anomalies:".bright_red().bold());
    println!("{}", "─".repeat(80).bright_black());
    for (i, anomaly) in anomalies.iter().enumerate() {
        if let Anomaly::EventStorm { .. } = anomaly {
            println!(
                "\n{} [{}] {}",
                format!("{}.", i + 1).bright_white(),
                severity_color(anomaly.severity()),
                anomaly.description().bright_white().bold()
            );
            continue;
        }
        let event = anomaly.event();
        println!(
            "\n{} [{}] {}",
            format!("{}.", i + 1).bright_white(),
            severity_color(anomaly.severity()),
            anomaly.description().bright_white().bold()
        );
        println!(
            "   {} {}",
            "Time:".bright_black(),
            event.system().time_created.system_time
        );
        let (_, process_name) = get_process_and_color(event);
        println!(
            "   {} {}",
            "Process:".bright_black(),
            process_name.bright_cyan()
        );
        if let Some(cmd) = get_command_line(event) {
            println!("   {} {}", "Command:".bright_black(), truncate(&cmd, 70));
        }
        if let Some(parent) = get_parent_image(event) {
            println!(
                "   {} {}",
                "Parent:".bright_black(),
                parent.bright_magenta()
            );
        }
    }
    println!("\n{}", "─".repeat(80).bright_black());
    println!("\n{}", "─".repeat(80).bright_black());
    println!(
        "{} Total anomalies found: {}\n",
        "\u{26A0}".bright_yellow(),
        anomalies.len().to_string().bright_red().bold()
    );
}
/// Display anomalies for live mode (more compact)
pub fn display_anomalies_live(anomalies: &[Anomaly]) {
    for anomaly in anomalies {
        println!(
            "{} [{}] {}",
            "\u{26A0}".bright_red().bold(),
            severity_color(anomaly.severity()),
            anomaly.description().bright_yellow().bold()
        );
    }
}
/// Format a single event for compact live monitoring
pub fn print_compact_event(event: &SysmonEvent, count: usize) {
    let (color, process_name) = get_process_and_color(event);
    let details = format_event_details(event);

    print!(
        "[{}] {} {} {} {} ",
        event.system().time_created.system_time.bright_black(),
        format!("#{}", count).dimmed(),
        format!("ID:{}", event.system().event_id.event_id).bright_yellow(),
        process_name.color(color),
        "->".bright_black()
    );

    println!("{}", truncate(&details, 80));
}
/// Get a colored string for severity
fn severity_color(severity: Severity) -> ColoredString {
    match severity {
        Severity::Critical => "CRITICAL".bright_red().bold(),
        Severity::High => "HIGH".bright_red().bold(),
        Severity::Medium => "MEDIUM".bright_yellow().bold(),
        Severity::Low => "LOW".bright_blue().bold(),
    }
}
/// Get the primary process name and risk color
fn get_process_and_color(event: &SysmonEvent) -> (Color, String) {
    let image = match &event {
        SysmonEvent::ProcessCreate(event) => &event.event_data.image,
        SysmonEvent::InboundNetwork(event) => &event.event_data.image,
        SysmonEvent::OutboundNetwork(event) => &event.event_data.image,
        SysmonEvent::FileCreate(event) => &event.event_data.image,
    };
    let process_name = image
        .rsplit('\\')
        .next()
        .unwrap_or(image.image.as_str())
        .to_string();
    let lower_name = process_name.to_lowercase();
    let shell = vec![
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "sh.exe",
        "bash.exe",
        "zsh.exe",
    ];
    let color = if shell.contains(&lower_name.as_str()) {
        Color::Red // High risk
    } else if event.system().event_id.event_id == 3 {
        Color::Blue // Network event (Event ID 3)
    } else if lower_name == "svchost.exe" {
        Color::Yellow // Suspicious
    } else {
        Color::Green // Normal
    };

    (color, process_name)
}
pub fn format_event_details(event: &SysmonEvent) -> String {
    let id = event.system().event_id.event_id;
    match &event {
        SysmonEvent::ProcessCreate(event) => event.event_data.command_line.to_string(),
        SysmonEvent::InboundNetwork(event) | SysmonEvent::OutboundNetwork(event) => {
            let data = &event.event_data;
            format!(
                "{} -> {}:{}",
                data.protocol, data.destination_ip, data.destination_port
            )
        }
        SysmonEvent::FileCreate(event) => {
            format!("File: {}", event.event_data.target_filename)
        }
    }
}
fn get_command_line(event: &SysmonEvent) -> Option<String> {
    match &event {
        SysmonEvent::ProcessCreate(event) => {
            Some(event.event_data.command_line.command_line.clone())
        }
        _ => None,
    }
}
fn get_parent_image(event: &SysmonEvent) -> Option<String> {
    match &event {
        SysmonEvent::ProcessCreate(event) => Some(event.event_data.parent_image.image.clone()),
        _ => None,
    }
}
/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
