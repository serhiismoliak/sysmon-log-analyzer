use crate::filters::EventFilter;
use crate::sysmon::Event as SysmonEvent;
use crate::{analyzer, display, parser};
use anyhow::{Result, anyhow};
use colored::Colorize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
use windows::{
    Win32::{Foundation::*, System::EventLog::*},
    core::*,
};
const BUFFER_SIZE: usize = 1000;

pub fn start_monitoring(filter: EventFilter, detect: bool) -> Result<Vec<SysmonEvent>> {
    info!("Starting live monitoring");
    verify_sysmon_channel()?;
    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!(
            "\n{}",
            "Received stop signal... shutting down.".bright_yellow()
        );
        r.store(false, Ordering::SeqCst);
    })?;
    let events_buffer = Arc::new(Mutex::new(VecDeque::with_capacity(BUFFER_SIZE)));
    let sub_result =
        unsafe { subscribe_to_events(filter, detect, running.clone(), events_buffer.clone()) };
    if let Err(e) = sub_result {
        error!("Error subscribing to events failed: {}", e);
        return Err(e);
    }
    info!("Monitoring stopped.");
    let final_buffer = Arc::try_unwrap(events_buffer)
        .map_err(|_| anyhow::anyhow!("Failed to unwrap events buffer"))?
        .into_inner()?;
    Ok(final_buffer.into_iter().collect())
}
fn verify_sysmon_channel() -> Result<()> {
    let channel = w!("Microsoft-Windows-Sysmon/Operational");
    unsafe {
        let handle = EvtOpenChannelConfig(None, channel, 0);
        if let Err(e) = handle {
            return Err(anyhow!(
                "Sysmon channel not found or inaccessible!\n\
                Error: {e}\n\
                Possible reasons:\n\
                1. Sysmon is not installed.\n\
                2. Sysmon service is not running.\n\
                3. Application was not run as administrator."
            ));
        }
        let _ = EvtClose(handle?);
    }
    println!("{}", "Sysmon channel verified.".bright_green());
    Ok(())
}
unsafe fn subscribe_to_events(
    filter: EventFilter,
    detect: bool,
    running: Arc<AtomicBool>,
    events_buffer: Arc<Mutex<VecDeque<SysmonEvent>>>,
) -> Result<()> {
    unsafe {
        let channel_path = w!("Microsoft-Windows-Sysmon/Operational");
        let query = build_xpath_query(&filter);
        let query_wide = HSTRING::from(&query);
        debug!("XPath query: {}", query);
        println!(
            "{}",
            "Subscription active. Waiting for events...\n".bright_green()
        );
        let signal_event = CreateEventW(None, true, false, None)?;
        let subscription = EvtSubscribe(
            None,
            Some(signal_event),
            channel_path,
            &query_wide,
            None,
            None,
            None,
            EvtSubscribeToFutureEvents.0,
        )?;
        let mut event_count = 0;

        while running.load(Ordering::SeqCst) {
            let wait_result = WaitForSingleObject(signal_event, 1000); // 1 second timeout
            if wait_result == WAIT_OBJECT_0 {
                ResetEvent(signal_event)?;
                loop {
                    let mut events: [isize; 16] = [EVT_HANDLE::default().0; 16];
                    let mut returned = 0u32;
                    let result = EvtNext(subscription, &mut events, 0, 0, &mut returned);
                    if let Err(e) = result {
                        if e.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                            break;
                        }
                        error!("EvtNext failed: {}", e);
                        break;
                    }
                    if returned == 0 {
                        break;
                    }
                    for i in 0..returned as isize {
                        let event_handle = events[i as usize];
                        match process_event_handle(EVT_HANDLE(i), &filter) {
                            Ok(Some(event)) => {
                                event_count += 1;
                                display::print_compact_event(&event, event_count);
                                let mut buffer = events_buffer.lock().unwrap();
                                if detect {
                                    let anomalies =
                                        analyzer::detect_anomalies_live(&event, &buffer);
                                    if !anomalies.is_empty() {
                                        display::display_anomalies_live(&anomalies);
                                    }
                                }
                                // If Buffer is full, keep it at max size
                                if buffer.len() == BUFFER_SIZE {
                                    buffer.pop_front();
                                }
                                buffer.push_back(event);
                            }
                            Ok(None) => {
                                // Ignore: Event was filtered out
                            }
                            Err(e) => {
                                warn!("Failed to parse event: {}", e);
                            }
                        }
                        let _ = EvtClose(EVT_HANDLE(event_handle));
                    }
                }
            } else if wait_result == WAIT_TIMEOUT {
                continue;
            }
        }
        let _ = EvtClose(subscription);
        let _ = CloseHandle(signal_event);

        info!("Processed {} events", event_count);
        println!(
            "\n{}",
            format!("Processed {event_count} events:").bright_green()
        );
        Ok(())
    }
}

/// Process a single event handle from the subscription
unsafe fn process_event_handle(
    event_handle: EVT_HANDLE,
    filter: &EventFilter,
) -> Result<Option<SysmonEvent>> {
    unsafe {
        let event_xml = render_event_xml(event_handle)?;
        match parser::parse_xml_event(&event_xml) {
            Ok(event) => {
                if filter.matches(&event) {
                    Ok(Some(event))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                debug!("Failed to deserialize event: {}", e);
                Err(e)
            }
        }
    }
}

/// Render the event data to an XML string
unsafe fn render_event_xml(event_handle: EVT_HANDLE) -> Result<String> {
    unsafe {
        let mut buffer_size = 0u32;
        let mut buffer_used = 0u32;
        let mut property_count = 0u32;
        let _ = EvtRender(
            None,
            event_handle,
            EvtRenderEventXml.0,
            0,
            None,
            &mut buffer_size,
            &mut property_count,
        );

        let mut str_buffer = vec![0u16; (buffer_size / 2) as usize + 1];
        EvtRender(
            None,
            event_handle,
            EvtRenderEventXml.0,
            buffer_size,
            Some(str_buffer.as_mut_ptr() as *mut _),
            &mut buffer_used,
            &mut property_count,
        )?;
        // Null terminate the string
        str_buffer[buffer_used as usize / 2] = 0;
        let pcwstr = PCWSTR(str_buffer.as_ptr());
        let xml_string = pcwstr.to_string()?;
        Ok(xml_string)
    }
}
/// Build the XPath query to pre-filter events at the API level
fn build_xpath_query(filter: &EventFilter) -> String {
    let mut condition = Vec::new();
    if let Some(ids) = filter.get_event_ids() {
        if ids.is_empty() {
            let id_conditions: Vec<String> = ids.iter().map(|id| format!("EventID={id}")).collect();
            condition.push(id_conditions.join(" or "));
        }
    }

    // Here we are building the query for the event filter
    if condition.is_empty() {
        "*".to_string()
    } else {
        format!("*[System[{}]", condition.join("  and "))
    }
}
