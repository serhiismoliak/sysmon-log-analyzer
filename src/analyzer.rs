#![allow(dead_code)]
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Display;
use chrono::{DateTime, Duration, Utc};
use crate::sysmon::{Event as SysmonEvent, NetworkEvent, ProcessCreateEvent};
use tracing::{debug, info};
use crate::helpers::HasSystem;

#[derive(Debug, Clone)]
pub enum Anomaly {
    UntrustedExecutable {
        event: SysmonEvent,
        reason: String,
    },
    SuspiciousParentChild {
        event: SysmonEvent,
        parent: String,
        child: String,
        reason: String,
    },
    DeepProcessTree {
        event: SysmonEvent,
        depth: usize,
    },
    UnusualPort {
        event: SysmonEvent,
        port: u16,
        process: String,
    },
    EventStorm {
        event_id: u8,
        count: usize,
        time_window_seconds: i64,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
impl Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}
/// Detect anomalies for a single live event (for `watch` command)
pub fn detect_anomalies_live(event: &SysmonEvent, context: &VecDeque<SysmonEvent>) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();
    match &event {
        SysmonEvent::ProcessCreate(event) => {
            if let Some(anomaly) = check_suspicious_parent_child(event) {
                anomalies.push(anomaly);
            }
            if let Some(anomaly) = check_process_depth(event, context) {
                anomalies.push(anomaly);
            }
            if let Some(anomaly) = check_event_storm_live(event, context) {
                anomalies.push(anomaly);
            }
        },
        SysmonEvent::OutboundNetwork(event) | SysmonEvent::InboundNetwork(event) => {
            if let Some(anomaly) = check_unusual_port(event) {
                anomalies.push(anomaly);
            }
            if let Some(anomaly) = check_unusual_port(event) {
                anomalies.push(anomaly);
            }
        },
        SysmonEvent::FileCreate(event) => {}
    }
    anomalies
}

impl Anomaly {
    pub fn severity(&self) -> Severity {
        match self {
            Anomaly::UntrustedExecutable { reason, .. } => {
                if reason.contains("Invalid") { Severity::High } else { Severity::Medium }
            },
            Anomaly::SuspiciousParentChild { .. } => Severity::High,
            Anomaly::DeepProcessTree { depth, .. } if *depth > 7 => Severity::High,
            Anomaly::DeepProcessTree { .. } => Severity::Medium,
            Anomaly::UnusualPort { .. } => Severity::Medium,
            Anomaly::EventStorm { .. } => Severity::High,
        }
    }
    pub fn description(&self) -> String {
        match self {
            Anomaly::UntrustedExecutable { reason, .. } => {
                format!("Untrusted Executable: {}", reason)
            }
            Anomaly::SuspiciousParentChild { parent, child, reason, .. } => {
                format!("Suspicious Process Chain: {} -> {} ({})", parent, child, reason)
            }
            Anomaly::DeepProcessTree { depth, .. } => {
                format!("Deep Process Nesting: {} levels", depth)
            }
            Anomaly::UnusualPort { port, process, .. } => {
                format!("Unusual Network Port: {} used by {}", port, process)
            }
            Anomaly::EventStorm { event_id, count, time_window_seconds } => {
                format!("Event Storm: ID {} ({} events in {}s)", event_id, count, time_window_seconds)
            }
        }
    }
    pub fn event(&self) -> &SysmonEvent {
        match self {
            Anomaly::UntrustedExecutable { event, .. }
            | Anomaly::SuspiciousParentChild { event, .. }
            | Anomaly::DeepProcessTree { event, .. }
            | Anomaly::UnusualPort { event, .. } => event,
            Anomaly::EventStorm { .. } => panic!("EventStorm anomaly does not have a associated event"),
        }
    }
}

const DEEP_NESTING_THRESHOLD: usize = 5;
const UNUSUAL_PORT_THRESHOLD: u16 = 49152;
const EVENT_STORM_THRESHOLD_COUNT: usize = 50;
const EVENT_STORM_WINDOW_SECONDS: usize = 10;

pub fn detect_anomalies(events: &[SysmonEvent]) -> Vec<Anomaly> {
    let mut detector = AnomalyDetector::new();
    detector.analyze_batch(events)
}
struct AnomalyDetector {
    anomalies: Vec<Anomaly>,
    /// Maps Parent PID to Vector of Child PID
    process_chains: HashMap<u64, Vec<u64>>,
    /// Maps PID to Depth
    process_depth: HashMap<u64, usize>,
    /// Maps EventID to Timestamps
    event_counts: HashMap<u8, Vec<DateTime<Utc>>>,
}
impl AnomalyDetector {
    fn new() -> Self {
        Self {
            anomalies: vec![],
            process_chains: HashMap::new(),
            process_depth: HashMap::new(),
            event_counts: HashMap::new(),
        }
    }
    fn analyze_batch(&mut self, events: &[SysmonEvent]) -> Vec<Anomaly> {
        info!("Starting batch anomaly detection on {} events", events.len());

        let mut sorted_events = events.to_vec();
        sorted_events.sort_by_key(|event| event.system().time_created.system_time.clone());
        for event in &sorted_events {
            if let Ok(parsed_time) = event.system().time_created.system_time.parse() {
                self.event_counts
                    .entry(event.system().event_id.event_id)
                    .or_default()
                    .push(parsed_time);
            } else {
                info!("Failed to parse timestamp for event {}: '{}'",
                           event.system().event_id.event_id,
                           event.system().time_created.system_time);
                continue;
            }
            match event {
                SysmonEvent::ProcessCreate(event) => {
                    if let Some(anomaly) = check_suspicious_parent_child(event) {
                        self.anomalies.push(anomaly)
                    }
                    self.check_process_depth_batch(event);
                },
                SysmonEvent::OutboundNetwork(event) => {
                    if let Some(anomaly) = check_unusual_port(event) {
                        self.anomalies.push(anomaly);
                    }
                }
                _ => {}
            }
        }
        self.check_event_storms_batch();
        info!("Finished batch anomaly detection on {} events", events.len());
        self.anomalies.clone()
    }
    fn check_process_depth_batch(&mut self, event: &ProcessCreateEvent) {
        let data = &event.event_data;
        let pid = data.process_id;
        let parent_pid = data.parent_process_id;
        let parent_depth = self.process_depth.get(&parent_pid).cloned().unwrap_or(0);
        let current_depth = parent_depth + 1;
        self.process_depth.insert(pid, current_depth);
        self.process_chains
            .entry(parent_pid)
            .or_default()
            .push(pid);
        if current_depth > DEEP_NESTING_THRESHOLD {
            self.anomalies.push(Anomaly::DeepProcessTree {
                event: SysmonEvent::ProcessCreate(event.clone()),
                depth: current_depth,
            });
        }
    }

    fn check_event_storms_batch(&mut self) {
        for (event_id, timestamp) in &self.event_counts {
            if timestamp.len() < EVENT_STORM_THRESHOLD_COUNT {
                continue;
            }
            for window in timestamp.windows(EVENT_STORM_WINDOW_SECONDS) {
                let start_time = window[0];
                let end_time = window[window.len() - 1];
                let duration = end_time.signed_duration_since(start_time).num_seconds();
                if duration <= EVENT_STORM_WINDOW_SECONDS as i64 {
                    self.anomalies.push(Anomaly::EventStorm {
                        event_id: *event_id,
                        count: EVENT_STORM_THRESHOLD_COUNT,
                        time_window_seconds: duration,
                    });
                    break;
                }
            }
        }
    }
}
// Individual Anomaly Checks
/// Check for suspicious parent-child process relationships
fn check_suspicious_parent_child(event: &ProcessCreateEvent) -> Option<Anomaly> {
    let parent = &event.event_data.parent_image;
    let child = &event.event_data.image;
    let parent_name = parent.image.rsplit('\\').next().unwrap_or(parent.image.as_str());
    let child_name = child.rsplit('\\').next().unwrap_or(child.image.as_str());
    let parent_lower = parent_name.to_lowercase();
    let child_lower = child_name.to_lowercase();

    // Here come rules for parent child relationship
    // Rule: svchost.exe should only be spawned by services.exe
    if child_lower == "svchost.exe" && parent_lower != "services.exe" {
        return Some(Anomaly::SuspiciousParentChild {
            event: SysmonEvent::ProcessCreate(event.clone()),
            parent: parent_name.to_string(),
            child: child_name.to_string(),
            reason: "svchost.exe is spawned by a non-service process".to_string(),
        })
    }
    // Rule: Office apps spawning shells
    let office_apps = ["winword.exe", "excel.exe", "powerpnt.exe"];
    let shell_processes = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"];

    if office_apps.contains(&parent_lower.as_str()) && shell_processes.contains(&child_lower.as_str()) {
        return Some(Anomaly::SuspiciousParentChild {
            event: SysmonEvent::ProcessCreate(event.clone()),
            parent: parent_name.to_string(),
            child: child_name.to_string(),
            reason: "Office application spawned a shell".to_string(),
        });
    }
    None
}
/// Checks for unusual port usage in outbound network events.
fn check_unusual_port(event: &NetworkEvent) -> Option<Anomaly> {
    let data = &event.event_data;
    if let (port, image, true) = (data.destination_port, &data.image, data.initiated) {
        if port >= UNUSUAL_PORT_THRESHOLD {
            let process = image.rsplit('\\').next().unwrap_or(image).to_string();
            return Some(Anomaly::UnusualPort {
                event: SysmonEvent::OutboundNetwork(event.clone()),
                port,
                process,
            });
        }
    }
    None
}
/// Check process depth context buffer (for live analysis)
fn check_process_depth(event: &ProcessCreateEvent, context: &VecDeque<SysmonEvent>) -> Option<Anomaly> {
    let data = &event.event_data;
    let parent_pid = data.parent_process_id;
    let mut depth = 1;
    let mut current_pid = parent_pid;
    let mut visited = HashSet::new();
    visited.insert(data.process_id);
    while current_pid != 0 && visited.insert(current_pid) {
        if let Some(parent_event) = context.iter().rev().find(|e|{
            if let SysmonEvent::ProcessCreate(e) = e {
                e.event_data.process_id == current_pid
            } else {
                false
            }
        }) {
            if let SysmonEvent::ProcessCreate(e) = parent_event {
                current_pid = e.event_data.parent_process_id;
                depth += 1;
            } else {
                break;
            }
        }
    }
    if depth > DEEP_NESTING_THRESHOLD {
        return Some(Anomaly::DeepProcessTree {
            event: SysmonEvent::ProcessCreate(event.clone()),
            depth,
        });
    }
    None
}
/// Stateful check for event storms using context buffer (for live analysis)
fn check_event_storm_live(event: &ProcessCreateEvent, context: &VecDeque<SysmonEvent>) -> Option<Anomaly> {
    let event_id = event.system().event_id.event_id;
    let window_end_time = match DateTime::parse_from_rfc3339(&event.system().time_created.system_time) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => return None, // skip malformed time
    };
    let window_start_time = window_end_time - Duration::seconds(EVENT_STORM_WINDOW_SECONDS as i64);
    let mut count = 0;
    for e in context.iter().rev() {
        let e_time = match DateTime::parse_from_rfc3339(&e.system().time_created.system_time) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => continue, // skip invalid timestamps
        };
        // Stop when the event is too old
        if e_time < window_start_time {
            break;
        }
        count += 1;
    }
    if count >= EVENT_STORM_THRESHOLD_COUNT {
        return Some(Anomaly::EventStorm {
            event_id,
            count,
            time_window_seconds: EVENT_STORM_WINDOW_SECONDS as i64,
        });
    }
    None
}
