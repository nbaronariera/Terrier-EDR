use core::fmt;

use strum_macros::FromRepr;

#[derive(Debug, PartialEq, Eq, FromRepr, Clone, Copy)]
#[repr(u8)]
pub enum FileOperation {
    Open = 0,
    Write = 1,
    Read = 2,
    Rename = 3,
    Move = 4,
    Link = 5,
    Unlink = 6,
}

#[derive(Debug, PartialEq, FromRepr, Clone, Copy)]
#[repr(u8)]
pub enum EventKind {
    Process = 0,
    File = 1,
    Net = 2,
}

#[derive(Copy, Clone, Debug)]
pub struct RawEvent<'a> {
    pub header: RawEventHeader,
    pub payload: RawEventPayload,
    pub tail: Option<&'a [u8]>,
}

#[derive(Copy, Clone, Debug)]
pub enum RawEventPayload {
    Process(RawProcessPayload),
    File(RawFilePayload),
    Net(RawNetPayload),
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawEventHeader {
    pub event_type: u8,
    pub total_length: u32,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawNetPayload {
    pub origin_ip: u32,
    pub target_ip: u32,
    pub origin_port: u16,
    pub target_port: u16,
    pub protocol: u8,
    pub result: u8,
    pub direction: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawProcessPayload {
    pub process_id: u32,
    pub ancestor_id: u32,
    pub inode: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawFilePayload {
    pub operation: u8,
    pub inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseEventError {
    HeaderTruncated,
    BufferTooSmallForLength,
    UnknownEventType,
    InvalidTotalLength,
}

impl fmt::Display for ParseEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTruncated => write!(f, "Buffer demasiado pequeño para leer la cabecera"),
            Self::BufferTooSmallForLength => write!(
                f,
                "El total_length de la cabecera excede el buffer proporcionado"
            ),
            Self::UnknownEventType => write!(f, "Tipo de evento desconocido o inválido"),
            Self::InvalidTotalLength => {
                write!(f, "El total_length es menor que el tamaño base del evento")
            }
        }
    }
}

pub fn parse_event<'a>(raw_bytes: &'a [u8]) -> Result<RawEvent<'a>, ParseEventError> {
    let header_size = size_of::<RawEventHeader>();

    if raw_bytes.len() < header_size {
        return Err(ParseEventError::HeaderTruncated);
    }

    let header = unsafe { core::ptr::read_unaligned(raw_bytes.as_ptr() as *const RawEventHeader) };
    let total_len = header.total_length as usize;

    if raw_bytes.len() < total_len {
        return Err(ParseEventError::BufferTooSmallForLength);
    }

    let kind = EventKind::from_repr(header.event_type).ok_or(ParseEventError::UnknownEventType)?;

    let payload_size = match kind {
        EventKind::Process => size_of::<RawProcessPayload>(),
        EventKind::File => size_of::<RawFilePayload>(),
        EventKind::Net => size_of::<RawNetPayload>(),
    };

    let tail_start = header_size + payload_size;
    if total_len < tail_start {
        return Err(ParseEventError::InvalidTotalLength);
    }

    let event_bytes = &raw_bytes[..total_len];
    let payload_bytes = &event_bytes[header_size..tail_start];

    let payload = match kind {
        EventKind::Process => {
            let p = unsafe {
                core::ptr::read_unaligned(payload_bytes.as_ptr() as *const RawProcessPayload)
            };
            RawEventPayload::Process(p)
        }
        EventKind::File => {
            let p = unsafe {
                core::ptr::read_unaligned(payload_bytes.as_ptr() as *const RawFilePayload)
            };
            RawEventPayload::File(p)
        }
        EventKind::Net => {
            let p = unsafe {
                core::ptr::read_unaligned(payload_bytes.as_ptr() as *const RawNetPayload)
            };
            RawEventPayload::Net(p)
        }
    };

    let tail_len = total_len - tail_start;
    let tail = if tail_len > 0 {
        Some(&event_bytes[tail_start..])
    } else {
        None
    };

    Ok(RawEvent {
        header,
        payload,
        tail,
    })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    fn struct_to_bytes<T: Copy>(data: &T) -> std::vec::Vec<u8> {
        let size = size_of::<T>();
        let mut buf = vec![0u8; size];
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut T, *data);
        }
        buf
    }

    fn build_raw_buffer<P: Copy>(
        mut header: RawEventHeader,
        payload: &P,
        tail: Option<&[u8]>,
        override_total_length: Option<u32>,
        out_buf: &mut [u8],
    ) -> usize {
        let header_sz = size_of::<RawEventHeader>();
        let payload_sz = size_of::<P>();
        let tail_sz = tail.map_or(0, |t| t.len());

        let real_length = header_sz + payload_sz + tail_sz;

        header.total_length = override_total_length.unwrap_or(real_length as u32);

        out_buf[..header_sz].copy_from_slice(struct_to_bytes(&header).as_slice());

        out_buf[header_sz..header_sz + payload_sz]
            .copy_from_slice(struct_to_bytes(payload).as_slice());

        if let Some(t) = tail {
            out_buf[header_sz + payload_sz..real_length].copy_from_slice(t);
        }

        real_length
    }

    fn default_header(event_type: EventKind) -> RawEventHeader {
        RawEventHeader {
            event_type: event_type as u8,
            total_length: 0,
            timestamp: 123456789,
            pid: 1000,
            uid: 1000,
        }
    }

    fn default_process_payload() -> RawProcessPayload {
        RawProcessPayload {
            process_id: 1000,
            ancestor_id: 1,
            inode: 9999,
        }
    }

    fn default_file_payload() -> RawFilePayload {
        RawFilePayload {
            operation: 1,
            inode: 8888,
        }
    }

    fn default_net_payload(direction: u8) -> RawNetPayload {
        RawNetPayload {
            origin_ip: 0xC0A80001u32.to_be(),
            target_ip: 0x08080808u32.to_be(),
            origin_port: 443u16.to_be(),
            target_port: 54321u16.to_be(),
            protocol: 6,
            result: 0,
            direction,
        }
    }

    #[test]
    fn test_struct_sizes() {
        assert_eq!(size_of::<RawEventHeader>(), 24, "Header ABI mismatch");
        assert_eq!(
            size_of::<RawProcessPayload>(),
            16,
            "Process payload ABI mismatch"
        );
        assert_eq!(size_of::<RawFilePayload>(), 16, "File payload ABI mismatch");
        assert_eq!(size_of::<RawNetPayload>(), 16, "Net payload ABI mismatch");
    }

    #[test]
    fn test_err_header_truncated() {
        let buffer = [0u8; 4];
        let result = parse_event(&buffer);
        assert_eq!(result.unwrap_err(), ParseEventError::HeaderTruncated);
    }

    #[test]
    fn test_err_buffer_too_small_for_length() {
        let header = default_header(EventKind::Process);
        let payload = default_process_payload();

        let mut buf = [0u8; 256];
        let len = build_raw_buffer(header, &payload, None, Some(1000), &mut buf);

        let result = parse_event(&buf[..len]);
        assert_eq!(
            result.unwrap_err(),
            ParseEventError::BufferTooSmallForLength
        );
    }

    #[test]
    fn test_err_unknown_event_type() {
        let mut header = default_header(EventKind::Process);
        header.event_type = 255;
        let payload = default_process_payload();

        let mut buf = [0u8; 256];
        let len = build_raw_buffer(header, &payload, None, None, &mut buf);

        let result = parse_event(&buf[..len]);
        assert_eq!(result.unwrap_err(), ParseEventError::UnknownEventType);
    }

    #[test]
    fn test_err_invalid_total_length() {
        let header = default_header(EventKind::Process);
        let payload = default_process_payload();
        let invalid_length = (size_of::<RawEventHeader>() + 1) as u32;
        let mut buf = [0u8; 256];
        let len = build_raw_buffer(header, &payload, None, Some(invalid_length), &mut buf);

        let result = parse_event(&buf[..len]);
        assert_eq!(result.unwrap_err(), ParseEventError::InvalidTotalLength);
    }

    #[test]
    fn test_ok_process() {
        let header = default_header(EventKind::Process);
        let payload = default_process_payload();
        let tail_data = b"/usr/bin/bash";

        let mut buf = [0u8; 256];
        let len = build_raw_buffer(header, &payload, Some(tail_data), None, &mut buf);

        let event = parse_event(&buf[..len]).expect("Process parse failed");

        assert_eq!(event.header.pid, 1000);
        assert_eq!(event.tail.unwrap(), tail_data);

        if let RawEventPayload::Process(p) = event.payload {
            assert_eq!(p.process_id, 1000);
            assert_eq!(p.inode, 9999);
        } else {
            panic!("Parsed wrong payload type");
        }
    }

    #[test]
    fn test_ok_file() {
        let header = default_header(EventKind::File);
        let payload = default_file_payload();

        let mut buf = [0u8; 256];
        let len = build_raw_buffer(header, &payload, None, None, &mut buf);

        let event = parse_event(&buf[..len]).expect("File parse failed");
        assert!(event.tail.is_none());

        if let RawEventPayload::File(p) = event.payload {
            assert_eq!(p.operation, 1);
            assert_eq!(p.inode, 8888);
        } else {
            panic!("Parsed wrong payload type");
        }
    }

    #[test]
    fn test_ok_net() {
        let header_0 = default_header(EventKind::Net);
        let payload_0 = default_net_payload(0);
        let mut buf_0 = [0u8; 256];
        let len_0 = build_raw_buffer(header_0, &payload_0, None, None, &mut buf_0);

        let event_0 = parse_event(&buf_0[..len_0]).expect("Net parse failed");
        if let RawEventPayload::Net(p) = event_0.payload {
            assert_eq!(
                p.direction, 0,
                "Direction no sobrevivió el round-trip como 0"
            );
            assert_eq!(p.target_port, 54321u16.to_be());
        } else {
            panic!("Parsed wrong payload type");
        }

        let header_1 = default_header(EventKind::Net);
        let payload_1 = default_net_payload(1);
        let mut buf_1 = [0u8; 256];
        let len_1 = build_raw_buffer(header_1, &payload_1, None, None, &mut buf_1);

        let event_1 = parse_event(&buf_1[..len_1]).expect("Net parse failed");
        if let RawEventPayload::Net(p) = event_1.payload {
            assert_eq!(
                p.direction, 1,
                "Direction no sobrevivió el round-trip como 1"
            );
        } else {
            panic!("Parsed wrong payload type");
        }
    }
}
