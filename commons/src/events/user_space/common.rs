use alloc::string::String;

use super::{FileEvent, NetEvent, ProcessEvent};
use crate::events::{
    domain::{
        FileOperation, NetAddress,
        NetOperation::{self},
        NetProtocol::{self},
        NetResult,
    },
    wire::{RawEvent, RawEventPayload},
};

/// Evento ya validado y listo para consumir en espacio de usuario.
///
/// Combina los datos comunes a todo evento ([`EventCommon`]) con los
/// específicos de su tipo ([`EventType`]). Se obtiene con [`Event::from_raw`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub common: EventCommon,
    pub event_type: EventType,
}

/// Errores al convertir un [`RawEvent`] en un [`Event`].
///
/// Cubre la ausencia o corrupción de la ruta (tail) y los valores numéricos
/// de operación/dirección que no corresponden a ninguna variante conocida.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EventError {
    MissingRoute,
    InvalidRouteUtf8,
    InvalidFileOperation(u8),
}

impl Event {
    /// Convierte un evento crudo del ring buffer en un [`Event`] tipado.
    ///
    /// Copia la cabecera común, extrae la ruta del tail (quitando el `\0`
    /// final si lo hay), convierte las IPs de orden de red a tipos de dominio
    /// (los puertos ya llegan en orden del host) y traduce los códigos
    /// numéricos a enums. Devuelve [`EventError`] si algo no cuadra.
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

            RawEventPayload::NetIPv4(raw) => EventType::Net(NetEvent {
                origin: Some(NetAddress::new_ipv4(raw.origin_ip, raw.origin_port)),
                target: Some(NetAddress::new_ipv4(raw.target_ip, raw.target_port)),
                protocol: NetProtocol::from_u8(raw.protocol),
                result: NetResult::from_u8(raw.result),
                operation: NetOperation::from_u8(raw.operation),
            }),
            RawEventPayload::NetIPv6(raw) => EventType::Net(NetEvent {
                origin: Some(NetAddress::new_ipv6_bytes(raw.origin_ip, raw.origin_port)),
                target: Some(NetAddress::new_ipv6_bytes(raw.target_ip, raw.target_port)),
                protocol: NetProtocol::from_u8(raw.protocol),
                result: NetResult::from_u8(raw.result),
                operation: NetOperation::from_u8(raw.operation),
            }),
        };

        Ok(Event { common, event_type })
    }
}
/// Parte específica de un [`Event`] según su categoría.
///
/// Cada variante envuelve el struct con los campos propios de ese tipo de
/// evento: ejecución de procesos, acceso a ficheros o actividad de red.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    Process(ProcessEvent),
    File(FileEvent),
    Net(NetEvent),
}

/// Datos compartidos por todos los eventos.
///
/// PID y UID del proceso que lo generó, el timestamp del kernel en el que
/// se capturó y el identificador del host (de momento siempre `0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventCommon {
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub host: u32,
}

// NOTA: tests generados/asistidos por IA (Claude), regla 2 de CLAUDE.md.
#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;
    use crate::events::{
        domain::NetAddressProtocol,
        wire::{
            EventKind, RawEvent, RawEventHeader, RawEventPayload, RawFilePayload,
            RawNetIPv4Payload, RawProcessPayload,
        },
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
        operation: u8,
    ) -> RawEvent<'static> {
        RawEvent {
            header: header(EventKind::NetIPv4),
            payload: RawEventPayload::NetIPv4(RawNetIPv4Payload {
                origin_ip,
                target_ip,
                origin_port,
                target_port,
                protocol,
                operation,
                result,
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

    // IPs en orden de red y puertos ya en orden del host, como los escribe eBPF.
    #[test]
    fn net_decodes_big_endian_ips_and_host_order_ports() {
        let event = Event::from_raw(raw_net(
            0xC0A80001u32.to_be(),
            0x08080808u32.to_be(),
            443,
            54321,
            6,
            0,
            NetOperation::Connect.to_u8(),
        ))
        .unwrap();

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

    // Un valor con bytes distintos detecta cualquier intercambio de bytes de más.
    #[test]
    fn net_port_is_not_byte_swapped() {
        let event = Event::from_raw(raw_net(0, 0, 0x1234, 0xABCD, 6, 0, 0)).unwrap();
        match &event.event_type {
            EventType::Net(n) => {
                assert_eq!(n.origin.as_ref().unwrap().port, 0x1234);
                assert_eq!(n.target.as_ref().unwrap().port, 0xABCD);
            }
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }

    #[test]
    fn net_maps_bind_operation() {
        let event = Event::from_raw(raw_net(0, 0, 0, 0, 6, 0, NetOperation::Bind.to_u8())).unwrap();
        match &event.event_type {
            EventType::Net(n) => assert_eq!(n.operation, NetOperation::Bind),
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }

    #[test]
    fn net_unknown_protocol_is_unregistered() {
        let event = Event::from_raw(raw_net(0, 0, 0, 0, 47, 0, 0)).unwrap();
        match &event.event_type {
            EventType::Net(n) => assert_eq!(n.protocol, NetProtocol::UndefinedProtocol(47)),
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }

    #[test]
    fn net_unknown_operation_keeps_raw_value() {
        let event = Event::from_raw(raw_net(0, 0, 0, 0, 6, 0, 200)).unwrap();
        match &event.event_type {
            EventType::Net(n) => assert_eq!(n.operation, NetOperation::UndefinedOperation(200)),
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }

    #[test]
    fn net_failed_result_keeps_error_code() {
        let event = Event::from_raw(raw_net(0, 0, 0, 0, 17, 5, 0)).unwrap();
        match &event.event_type {
            EventType::Net(n) => {
                assert_eq!(n.protocol, NetProtocol::UDP);
                assert_eq!(n.result, NetResult::Failed(5));
            }
            other => panic!("esperaba Net, obtuvo {:?}", other),
        }
    }
}
