use sealed::sealed;
use sysmon::{Event, FileCreateEvent, NetworkEvent, ProcessCreateEvent, System};
use crate::helpers::__seal_has_system::Sealed;
#[sealed]
pub trait HasSystem {
    fn system(&self) -> &System;
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