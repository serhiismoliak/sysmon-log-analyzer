use crate::helpers::__seal_has_system::Sealed;
use crate::sysmon::{Event, FileCreateEvent, NetworkEvent, ProcessCreateEvent, System};
use sealed::sealed;
#[sealed]
pub trait HasSystem {
    fn system(&self) -> &System;
    fn name(&self) -> &str {
        event_name(self.system())
    }
}
fn event_name(system: &System) -> &'static str {
    match system.event_id.event_id {
        1 => "ProcessCreate",
        2 => "FileCreateTime",
        3 => "NetworkConnect",
        4 => "ServiceStateChange",
        5 => "ProcessTerminate",
        6 => "DriverLoad",
        7 => "ImageLoad",
        8 => "CreateRemoteThread",
        9 => "RawAccessRead",
        10 => "ProcessAccess",
        11 => "FileCreate",
        12 => "RegistryEvent",
        13 => "RegistryEventSetValue",
        14 => "RegistryEventRename",
        15 => "FileCreateStreamHash",
        16 => "ServiceConfigurationChange",
        17 => "PipeEventCreated",
        18 => "PipeEventConnected",
        19 => "WmiEventFilter",
        20 => "WmiEventConsumer",
        21 => "WmiEventConsumerToFilter",
        22 => "DNSEvent",
        23 => "FileDelete",
        24 => "ClipboardChange",
        25 => "ProcessTampering",
        26 => "FileDeleteDetected",
        27 => "FileBlockExecutable",
        28 => "FileBlockShredding",
        29 => "FileExecutableDetected",
        255 => "Error",
        _ => "Unknown",
    }
}
impl Sealed for ProcessCreateEvent {}
impl HasSystem for ProcessCreateEvent {
    fn system(&self) -> &System {
        &self.system
    }
}
impl Sealed for FileCreateEvent {}
impl HasSystem for FileCreateEvent {
    fn system(&self) -> &System {
        &self.system
    }
}
impl Sealed for NetworkEvent {}
impl HasSystem for NetworkEvent {
    fn system(&self) -> &System {
        &self.system
    }
}
impl Sealed for Event {}
impl HasSystem for Event {
    fn system(&self) -> &System {
        match self {
            Event::ProcessCreate(e) => e.system(),
            Event::FileCreate(e) => e.system(),
            Event::InboundNetwork(e) => e.system(),
            Event::OutboundNetwork(e) => e.system(),
        }
    }
}
