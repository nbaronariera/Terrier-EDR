//! Tests de integración del pipeline completo: bytes crudos -> parse_event -> Event::from_raw.
//!
//! Verifican los valores decodificados (no solo Ok/Err). Requieren el feature `user`
//! porque el módulo `events::user_space` está gateado tras `#[cfg(feature = "user")]`.
//!
//! Ejecutar con: `cargo test -p commons --features user`.
//!
//! Generados/asistidos por IA (CLAUDE.md, regla 2).

use core::{mem::size_of, net::Ipv4Addr};

use commons::events::{
    domain::{
        FileOperation, NetAddress, NetAddressProtocol, NetOperation, NetProtocol, NetResult,
    },
    user_space::{Event, EventError, EventType},
    wire::{
        EventKind, RawEventHeader, RawFilePayload, RawNetIPv4Payload, RawProcessPayload,
        parse_event,
    },
};

fn to_bytes<T: Copy>(value: &T) -> Vec<u8> {
    let mut buf = vec![0u8; size_of::<T>()];
    unsafe {
        core::ptr::write_unaligned(buf.as_mut_ptr() as *mut T, *value);
    }
    buf
}

fn build_event<P: Copy>(event_type: u8, payload: &P, tail: Option<&[u8]>) -> Vec<u8> {
    let mut header = RawEventHeader {
        event_type,
        total_length: 0,
        timestamp: 42,
        pid: 100,
        uid: 200,
    };

    let total = size_of::<RawEventHeader>() + size_of::<P>() + tail.map_or(0, |t| t.len());
    header.total_length = total as u32;

    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&to_bytes(&header));
    buf.extend_from_slice(&to_bytes(payload));
    if let Some(t) = tail {
        buf.extend_from_slice(t);
    }
    buf
}

#[test]
fn process_event_decodes_header_payload_and_route() {
    let bytes = build_event(
        EventKind::Process as u8,
        &RawProcessPayload {
            process_id: 1000,
            ancestor_id: 7,
            inode: 999,
        },
        Some(b"/usr/bin/bash\0"),
    );

    let raw = parse_event(&bytes).expect("parse_event falla");
    let event = Event::from_raw(raw).expect("from_raw falla");

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

// IPs en orden de red y puertos ya en orden del host, como los escribe eBPF.
#[test]
fn net_event_decodes_big_endian_ips_and_host_order_ports() {
    let bytes = build_event(
        EventKind::NetIPv4 as u8,
        &RawNetIPv4Payload {
            origin_ip: 0xC0A80001u32.to_be(),
            target_ip: 0x08080808u32.to_be(),
            origin_port: 443,
            target_port: 54321,
            protocol: 6,
            operation: NetOperation::Connect.to_u8(),
            result: 0,
        },
        None,
    );

    let raw = parse_event(&bytes).expect("parse_event falla");
    let event = Event::from_raw(raw).expect("from_raw falla");

    match &event.event_type {
        EventType::Net(n) => {
            assert_eq!(
                n.origin,
                Some(NetAddress {
                    ip: NetAddressProtocol::IPv4(Ipv4Addr::new(192, 168, 0, 1)),
                    port: 443
                })
            );
            assert_eq!(
                n.target,
                Some(NetAddress {
                    ip: NetAddressProtocol::IPv4(Ipv4Addr::new(8, 8, 8, 8)),
                    port: 54321
                })
            );
            assert_eq!(n.protocol, NetProtocol::TCP);
            assert_eq!(n.result, NetResult::Success);
            assert_eq!(n.operation, NetOperation::Connect);
        }
        other => panic!("esperaba Net, obtuvo {:?}", other),
    }
}

#[test]
fn file_event_decodes_route_inode_and_operation() {
    let bytes = build_event(
        EventKind::File as u8,
        &RawFilePayload {
            operation: FileOperation::Write as u8,
            inode: 888,
        },
        Some(b"/tmp/x"),
    );

    let raw = parse_event(&bytes).expect("parse_event falla");
    let event = Event::from_raw(raw).expect("from_raw falla");

    assert_eq!(event.common.pid, 100);
    match &event.event_type {
        EventType::File(f) => {
            assert_eq!(f.route, "/tmp/x");
            assert_eq!(f.inode, 888);
            assert_eq!(f.operation, FileOperation::Write);
        }
        other => panic!("esperaba File, obtuvo {:?}", other),
    }
}

#[test]
fn process_event_missing_tail_reports_missing_route() {
    let bytes = build_event(
        EventKind::Process as u8,
        &RawProcessPayload {
            process_id: 1,
            ancestor_id: 2,
            inode: 3,
        },
        None,
    );

    let raw = parse_event(&bytes).expect("parse_event falla");
    assert_eq!(Event::from_raw(raw).unwrap_err(), EventError::MissingRoute);
}

#[test]
fn process_event_invalid_utf8_tail_reports_error() {
    let bytes = build_event(
        EventKind::Process as u8,
        &RawProcessPayload {
            process_id: 1,
            ancestor_id: 2,
            inode: 3,
        },
        Some(&[0xFF, 0xFE]),
    );

    let raw = parse_event(&bytes).expect("parse_event falla");
    assert_eq!(
        Event::from_raw(raw).unwrap_err(),
        EventError::InvalidRouteUtf8
    );
}

#[test]
fn file_event_unknown_operation_reports_error() {
    let bytes = build_event(
        EventKind::File as u8,
        &RawFilePayload {
            operation: 200,
            inode: 5,
        },
        Some(b"/tmp/x"),
    );

    let raw = parse_event(&bytes).expect("parse_event falla");
    assert_eq!(
        Event::from_raw(raw).unwrap_err(),
        EventError::InvalidFileOperation(200)
    );
}

#[test]
fn net_event_unknown_operation_keeps_raw_value() {
    let bytes = build_event(
        EventKind::NetIPv4 as u8,
        &RawNetIPv4Payload {
            origin_ip: 0,
            target_ip: 0,
            origin_port: 0,
            target_port: 0,
            protocol: 6,
            operation: 200,
            result: 0,
        },
        None,
    );

    let raw = parse_event(&bytes).expect("parse_event falla");
    let event = Event::from_raw(raw).expect("from_raw falla");
    match &event.event_type {
        EventType::Net(n) => assert_eq!(n.operation, NetOperation::UndefinedOperation(200)),
        other => panic!("esperaba Net, obtuvo {:?}", other),
    }
}
