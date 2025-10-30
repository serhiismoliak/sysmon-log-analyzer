use chrono::NaiveDateTime;
use sysmon::{Event as SysmonEvent, NetworkEvent, System};
use tracing::debug;
use crate::helpers::HasSystem;


#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    event_ids: Option<Vec<u8>>,
    after: Option<NaiveDateTime>,
    before: Option<NaiveDateTime>,
    search_term: Option<String>,
}

impl EventFilter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_event_ids(mut self, ids: Option<Vec<u8>>) -> Self {
        self.event_ids = ids;
        self
    }
    pub fn with_time_range(mut self, after: Option<NaiveDateTime>, before: Option<NaiveDateTime>) -> Self {
        self.after = after;
        self.before = before;
        self
    }
    pub fn with_search_term(mut self, term: Option<String>) -> Self {
        self.search_term = term.map(|s| s.to_lowercase());
        self
    }
    pub fn get_event_ids(&self) -> Option<&Vec<u8>> {
        self.event_ids.as_ref()
    }
    pub fn matches(&self, event: &SysmonEvent) -> bool {
        if let Some(ref ids) = self.event_ids {
            if !ids.contains(&event.system().event_id.event_id) {
                return false;
            }
        }
        if let Some(after) = self.after {
            if event.system().time_created.system_time < after.to_string() {
                return false;
            }
        }
        if let Some(before) = self.before {
            if event.system().time_created.system_time > before.to_string() {
                return false;
            }
        }

        // Search term filter
        if let Some(ref search) = self.search_term {
            if !self.search_matches(event, search) {
                return false;
            }
        }

        true
    }
    pub fn search_matches(&self, event: &SysmonEvent, search: &str) -> bool {
        if event.system().computer.computer.to_lowercase().contains(search) {
            return true;
        }
        let check = |s: &str| s.to_lowercase().contains(&search);

        match event {
            SysmonEvent::ProcessCreate(proc) => {
                let data = &proc.event_data;
                check(&data.image.image)
                    || check(&data.command_line.command_line)
                    || check(&data.user.user)
                    || check(&data.parent_image.image)
            }

            SysmonEvent::FileCreate(file) => {
                let data = &file.event_data;
                check(&data.image.image)
                    || check(&data.target_filename)
            }

            SysmonEvent::InboundNetwork(net) | SysmonEvent::OutboundNetwork(net) => {
                let data = &net.event_data;
                check(&data.image)
                    || check(&data.destination_ip)
                    || check(&data.user.as_ref().map(|s| s.user.to_owned()).unwrap_or_else(|| "".to_string()))
            }
        }
    }
    pub fn apply(&self, events: &[SysmonEvent]) -> Vec<SysmonEvent> {
        events.iter().filter(
            |event| self.matches(event))
                .cloned()
                .collect()
    }
}