use std::path::{Path, PathBuf};
use evtx::{EvtxParser, ParserSettings};
use crate::sysmon::Event as SysmonEvent;
use anyhow::{Context, Result};
use tracing::{debug, warn};
pub fn parse_evtx_file(path: &Path) -> Result<Vec<SysmonEvent>> {
    let mut parser = EvtxParser::from_path(path)
        .with_context(|| format!("Failed to open: {}", path.to_string_lossy()))?
        .with_configuration(ParserSettings::default().num_threads(0));
    let mut events = Vec::new();

    for record in parser.records() {
        match record {
            Ok(record) => {
                match parse_xml_event(&record.data) {
                    Ok(event) => {
                        events.push(event);
                    },
                    Err(e) => debug!("Failed to parse record as Sysmon event: {}", e),
                }
            }
            Err(e) => warn!("Error reading EVTX record: {}", e),
        }
    }
    if events.is_empty() {
        warn!("No Sysmon events found in file: {}", path.to_string_lossy());
    } else {
        debug!("Parsed {} valid Sysmon events from {}", events.len(), path.to_string_lossy());
    }
    Ok(events)
}
/// Parse Sysmon XML event
pub fn parse_xml_event(xml: &str) -> anyhow::Result<SysmonEvent> {
    println!("{}", xml);
    SysmonEvent::from_str(&xml)
        .map_err(|e| anyhow::anyhow!("Failed to parse event XML: {}", e))
}


#[cfg(test)]
mod tests {
    use super::*;
    fn get_test_xml() -> &'static str {
        r#"
    <Event>
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{...}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2025-01-01T10:00:00.000Z"/>
    <EventRecordID>42</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1000" ThreadID="2000"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>TEST-PC</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="UtcTime">2025-01-01 10:00:00.000</Data>
    <Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
    <Data Name="ProcessId">1000</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c echo Hello</Data>
    <Data Name="CurrentDirectory">C:\Users\Test</Data>
    <Data Name="User">TEST-PC\Administrator</Data>
    <Data Name="LogonGuid">{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}</Data>
    <Data Name="LogonId">0x3e7</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">System</Data>
    <Data Name="Hashes">SHA1=1234567890ABCDEF</Data>
    <Data Name="ParentProcessGuid">{99999999-8888-7777-6666-555555555555}</Data>
    <Data Name="ParentProcessId">4321</Data>
    <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
    <Data Name="ParentCommandLine">explorer.exe</Data>
  </EventData>
</Event>
    "#
    }

    #[test]
    fn check_valid_process_create_event() {
        let xml = get_test_xml();

        let event = SysmonEvent::from_str(xml).expect("Should parse valid Sysmon ProcessCreate event");

        match event {
            SysmonEvent::ProcessCreate(ev) => {
                assert_eq!(ev.event_data.process_id, 1000);
                assert_eq!(ev.event_data.parent_process_id, 4321);
                assert!(ev.event_data.image.ends_with("cmd.exe"));
                assert!(ev.event_data.parent_image.ends_with("explorer.exe"));
            }
            _ => panic!("Expected ProcessCreate event"),
        }
    }
    #[test]
    fn parse_valid_process_create_event() {
        let xml = get_test_xml();
        let event = parse_xml_event(xml).expect("Should parse valid Sysmon ProcessCreate event");
        match event {
            SysmonEvent::ProcessCreate(ev) => {
                assert_eq!(ev.event_data.process_id, 1000);
                assert_eq!(ev.event_data.parent_process_id, 4321);
                assert!(ev.event_data.image.ends_with("cmd.exe"));
                assert!(ev.event_data.parent_image.ends_with("explorer.exe"));
            }
            _ => panic!("Expected ProcessCreate event"),
        }
    }
    #[test]
    fn test_parse_xml_event_invalid() {
        // Missing closing tag, malformed XML
        let bad_xml = "<System><EventID>1";
        let result = parse_xml_event(bad_xml);
        assert!(result.is_err(), "Expected error for malformed XML");
    }
}