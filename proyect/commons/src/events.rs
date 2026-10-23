use alloc::string::String;

use strum_macros::FromRepr;

use crate::{
    event_wire::{FileOperation, RawEvent, RawEventPayload},
    events::NetProtocol::Unregistered,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub common: EventCommon,
    pub event_type: EventType,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EventError {
    MissingRoute,
    InvalidRouteUtf8,
    InvalidFileOperation(u8),
    InvalidNetDirection(u8),
}

impl Event {
    pub fn from_raw(value: RawEvent<'_>) -> Result<Self, EventError> {
        let common = EventCommon {
            pid: value.header.pid,
            uid: value.header.uid,
            timestamp: value.header.timestamp,
            host: 0, // TODO: Falta el host
        };

        let extract_route = || -> Result<String, EventError> {
            let bytes = value.tail.ok_or(EventError::MissingRoute)?;

            let clean_bytes = if bytes.last() == Some(&0) {
                &bytes[..bytes.len() - 1]
            } else {
                bytes
            };

            String::from_utf8(clean_bytes.to_vec()).map_err(|_| EventError::InvalidRouteUtf8)
        };

        let event_type = match value.payload {
            RawEventPayload::Process(raw) => EventType::Process(ProcessEvent {
                process: raw.process_id,
                ancestor: raw.ancestor_id,
                inode: raw.inode,
                route: extract_route()?,
            }),

            RawEventPayload::File(raw) => EventType::File(FileEvent {
                route: extract_route()?,
                inode: raw.inode,
                operation: FileOperation::from_repr(raw.operation)
                    .ok_or(EventError::InvalidFileOperation(raw.operation))?,
            }),

            RawEventPayload::Net(raw) => EventType::Net(NetEvent {
                origin: NetAddress {
                    ip: u32::from_be(raw.origin_ip),
                    port: u16::from_be(raw.origin_port),
                },
                target: NetAddress {
                    ip: u32::from_be(raw.target_ip),
                    port: u16::from_be(raw.target_port),
                },
                protocol: NetProtocol::from_repr(raw.protocol)
                    .unwrap_or(Unregistered(raw.protocol)),
                result: NetResult::from_u8(raw.result),
                direction: match raw.direction {
                    0 => NetDirection::Inbound,
                    1 => NetDirection::Outbound,
                    _ => return Err(EventError::InvalidNetDirection(raw.direction)),
                },
            }),
        };

        Ok(Event { common, event_type })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    Process(ProcessEvent),
    File(FileEvent),
    Net(NetEvent),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventCommon {
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub host: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessEvent {
    pub process: u32,
    pub ancestor: u32,
    pub inode: u64,
    pub route: String,
    //args: u32, TODO
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEvent {
    pub route: String,
    pub inode: u64,
    pub operation: FileOperation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetEvent {
    pub origin: NetAddress,
    pub target: NetAddress,
    pub protocol: NetProtocol,
    pub result: NetResult,
    pub direction: NetDirection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetAddress {
    pub ip: u32,
    pub port: u16,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NetDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NetResult {
    Success,
    Failed(u8),
}

impl NetResult {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Success,
            err_code => Self::Failed(err_code),
        }
    }
}
#[derive(Debug, PartialEq, Eq, FromRepr, Clone, Copy)]
#[repr(u8)]
pub enum NetProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Unregistered(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_wire::{
        EventKind, FileOperation, RawEvent, RawEventHeader, RawEventPayload, RawFilePayload,
        RawNetPayload, RawProcessPayload,
    };

    fn header(kind: EventKind) -> RawEventHeader {
        RawEventHeader {
            event_type: kind as u8,
            total_length: 0,
            timestamp: 42,
            pid: 100,
            uid: 200,
        }
    }

    fn raw_process(tail: Option<&[u8]>) -> RawEvent<'_> {
        RawEvent {
            header: header(EventKind::Process),
            payload: RawEventPayload::Process(RawProcessPayload {
                process_id: 1000,
                ancestor_id: 7,
                inode: 999,
            }),
            tail,
        }
    }

    fn raw_file(operation: u8, tail: Option<&[u8]>) -> RawEvent<'_> {
        RawEvent {
            header: header(EventKind::File),
            payload: RawEventPayload::File(RawFilePayload {
                operation,
                inode: 888,
            }),
            tail,
        }
    }

    fn raw_net(
        origin_ip: u32,
        target_ip: u32,
        origin_port: u16,
        target_port: u16,
        protocol: u8,
        result: u8,
        direction: u8,
    ) -> RawEvent<'static> {
        RawEvent {
            header: header(EventKind::Net),
            payload: RawEventPayload::Net(RawNetPayload {
                origin_ip,
                target_ip,
                origin_port,
                target_port,
                protocol,
                result,
                direction,
            }),
            tail: None,
        }
    }

    #[test]
    fn process_maps_fields_and_strips_trailing_nul() {
        let event = Event::from_raw(raw_process(Some(b"/usr/bin/bash\0"))).unwrap();

        assert_eq!(event.common.pid, 100);
        assert_eq!(event.common.uid, 200);
        assert_eq!(event.common.timestamp, 42);

        match &event.event_type {
            EventType::Process(p) => {
                assert_eq!(p.process, 1000);
                assert_eq!(p.ancestor, 7);
                assert_eq!(p.inode, 999);
                assert_eq!(p.route, "/usr/bin/bash");
            }
            other => panic!("esperaba Process, obtuvo {:?}", other),
        }
    }

    #[test]
    fn process_route_without_nul_is_kept_verbatim() {
        let event = Event::from_raw(raw_process(Some(b"/usr/bin/bash"))).unwrap();
        match &event.event_type {
            EventType::Process(p) => assert_eq!(p.route, "/usr/bin/bash"),
            other => panic!("esperaba Process, obtuvo {:?}", other),
        }
    }

    #[test]
    fn process_missing_tail_is_missing_route() {
        assert_eq!(
            Event::from_raw(raw_process(None)).unwrap_err(),
            EventError::MissingRoute
        );
    }

    #[test]
    fn process_invalid_utf8_tail_is_error() {
        assert_eq!(
            Event::from_raw(raw_process(Some(&[0xFF, 0xFE]))).unwrap_err(),
            EventError::InvalidRouteUtf8
        );
    }

    #[test]
    fn process_empty_tail_yields_empty_route() {
        let event = Event::from_raw(raw_process(Some(b""))).unwrap();
        match &event.event_type {
            EventType::Process(p) => assert_eq!(p.route, ""),
            other => panic!("esperaba Process, obtuvo {:?}", other),
        }
    }

    #[test]
    fn file_maps_operation_and_route() {
        let event = Event::from_raw(raw_file(FileOperation::Write as u8, Some(b"/tmp/x"))).unwrap();
        match &event.event_type {
            EventType::File(f) => {
                assert_eq!(f.inode, 888);
                assert_eq!(f.operation, FileOperation::Write);
                assert_eq!(f.route, "/tmp/x");
            }
            other => panic!("esperaba File, obtuvo {:?}", other),
        }
    }

    #[test]
    fn file_unknown_operation_is_error() {
        assert_eq!(
            Event::from_raw(raw_file(200, Some(b"/tmp/x"))).unwrap_err(),
            EventError::InvalidFileOperation(200)
        );
    }

    #[test]
    fn net_decodes_big_endian_addresses_and_maps_fields() {
        let event = Event::from_raw(raw_net(
            0xC0A80001u32.to_be(),
            0x08080808u32.to_be(),
            443u16.to_be(),
            54321u16.to_be(),
            6,
            0,
            0,
        ))
        .unwrap();

        match &event.event_type {
            EventType::Net(n) => {
                assert_eq!(n.origin.ip, 0xC0A80001);
                assert_eq!(n.origin.port, 443);
                assert_eq!(n.target.ip, 0x08080808);
                assert_eq!(n.target.port, 54321);
                assert_eq!(n.protocol, NetProtocol::TCP);
                assert_eq!(n.result, NetResult::Success);
                assert_eq!(n.direction, NetDirection::Inbound);
            }
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }

    #[test]
    fn net_unknown_protocol_is_unregistered() {
        let event = Event::from_raw(raw_net(0, 0, 0, 0, 47, 0, 0)).unwrap();
        match &event.event_type {
            EventType::Net(n) => assert_eq!(n.protocol, NetProtocol::Unregistered(47)),
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }

    #[test]
    fn net_invalid_direction_is_error() {
        assert_eq!(
            Event::from_raw(raw_net(0, 0, 0, 0, 6, 0, 2)).unwrap_err(),
            EventError::InvalidNetDirection(2)
        );
    }

    #[test]
    fn net_outbound_and_failed_result() {
        let event = Event::from_raw(raw_net(0, 0, 0, 0, 17, 5, 1)).unwrap();
        match &event.event_type {
            EventType::Net(n) => {
                assert_eq!(n.protocol, NetProtocol::UDP);
                assert_eq!(n.result, NetResult::Failed(5));
                assert_eq!(n.direction, NetDirection::Outbound);
            }
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }
}
