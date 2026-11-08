use core::{fmt, ptr};

use commons::events::wire::{
    EventKind, RawEventHeader, RawEventPayload, RawFilePayload, RawNetIPv4Payload,
    RawNetIPv6Payload, RawProcessPayload,
};

use crate::event_assembly::{EVENTS, MAX_EVENT_SIZE, SCRATCHPAD};

/// Tamaño de [`RawEventHeader`].
pub const HEADER_SZ: usize = size_of::<RawEventHeader>();
/// Tamaño de [`RawProcessPayload`].
pub const PAYLOAD_SZ: usize = size_of::<RawProcessPayload>();
/// Tamaño de [`RawNetIPv4Payload`].
pub const NETV4_SZ: usize = size_of::<RawNetIPv4Payload>();
/// Tamaño de [`RawNetIPv6Payload`].
pub const NETV6_SZ: usize = size_of::<RawNetIPv6Payload>();
/// Tamaño de [`RawFilePayload`].
pub const FILE_SZ: usize = size_of::<RawFilePayload>();

/// Errores que puede devolver el [`EventBuilder`].
///
/// Fallo al reservar en el ring buffer, llamar a un método en un estado que
/// no toca, o haber perdido la reserva de memoria (ya enviada o descartada).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderError {
    ReserveFailed,
    InvalidState,
    MemoryLost,
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReserveFailed => write!(f, "Fallo al reservar memoria en el RingBuffer"),
            Self::InvalidState => write!(f, "Operación inválida para el estado actual del builder"),
            Self::MemoryLost => write!(f, "Pérdida inesperada de la memoria reservada"),
        }
    }
}

pub struct EventBuilder {
    start_ptr: *mut u8,
    ptr: *mut u8,
    state: BuilderState,
}

impl EventBuilder {
    #[allow(static_mut_refs)]
    pub fn new() -> Option<Self> {
        let start_ptr = unsafe { SCRATCHPAD.get_ptr_mut(0)? } as *mut u8;
        Some(Self {
            start_ptr,
            ptr: start_ptr,
            state: BuilderState::Ready,
        })
    }

    pub fn write_header(&mut self, event_type: EventKind) -> Result<&mut Self, BuilderError> {
        if self.state != BuilderState::Ready {
            return Err(BuilderError::InvalidState);
        }

        let header = RawEventHeader {
            event_type: event_type as u8,
            total_length: HEADER_SZ as u32,
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid: (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32,
            uid: aya_ebpf::helpers::bpf_get_current_uid_gid() as u32,
        };

        unsafe {
            ptr::write_unaligned(self.ptr as *mut RawEventHeader, header);
            self.ptr = self.ptr.add(HEADER_SZ);
        }
        self.state = BuilderState::HeaderWritten;

        Ok(self)
    }

    pub fn write_payload(&mut self, payload: RawEventPayload) -> Result<&mut Self, BuilderError> {
        if self.state != BuilderState::HeaderWritten {
            return Err(BuilderError::InvalidState);
        }

        unsafe {
            match payload {
                RawEventPayload::Process(p) => {
                    ptr::write_unaligned(self.ptr as *mut RawProcessPayload, p);
                    self.ptr = self.ptr.add(PAYLOAD_SZ);
                    self.add_total_length(PAYLOAD_SZ);
                }
                RawEventPayload::File(p) => {
                    ptr::write_unaligned(self.ptr as *mut RawFilePayload, p);
                    self.ptr = self.ptr.add(FILE_SZ);
                    self.add_total_length(FILE_SZ);
                }
                RawEventPayload::NetIPv4(p) => {
                    ptr::write_unaligned(self.ptr as *mut RawNetIPv4Payload, p);
                    self.ptr = self.ptr.add(NETV4_SZ);
                    self.add_total_length(NETV4_SZ);
                }
                RawEventPayload::NetIPv6(p) => {
                    ptr::write_unaligned(self.ptr as *mut RawNetIPv6Payload, p);
                    self.ptr = self.ptr.add(NETV6_SZ);
                    self.add_total_length(NETV6_SZ);
                }
            }
        }
        self.state = BuilderState::PayloadWritten;
        Ok(self)
    }

    pub fn get_tail(&mut self) -> Option<&mut [u8]> {
        if self.state == BuilderState::PayloadWritten {
            let bytes_written = (self.ptr as usize) - (self.start_ptr as usize);
            let tail_len = MAX_EVENT_SIZE - bytes_written;

            unsafe {
                return Some(core::slice::from_raw_parts_mut(self.ptr, tail_len));
            }
        }
        None
    }

    pub fn end_tail_write(&mut self, length: u32) -> Result<&mut Self, BuilderError> {
        if self.state != BuilderState::PayloadWritten {
            return Err(BuilderError::InvalidState);
        }

        self.add_total_length(length as usize);

        unsafe {
            self.ptr = self.ptr.add(length as usize);
        }

        self.state = BuilderState::TailWritten;
        Ok(self)
    }

    #[allow(static_mut_refs)]
    pub fn submit(&mut self) -> Result<(), BuilderError> {
        if self.state != BuilderState::TailWritten && self.state != BuilderState::PayloadWritten {
            return Err(BuilderError::InvalidState);
        }

        let bytes_written = (self.ptr as usize) - (self.start_ptr as usize);
        let slice = unsafe { core::slice::from_raw_parts(self.start_ptr, bytes_written) };
        let _ = unsafe { EVENTS.output::<[u8]>(slice, 0) };

        self.state = BuilderState::Closed;
        Ok(())
    }

    pub fn discard(mut self) {
        self.state = BuilderState::Closed;
    }

    fn add_total_length(&mut self, size: usize) {
        let header = self.start_ptr as *mut RawEventHeader;
        unsafe {
            let len_ptr = ptr::addr_of_mut!((*header).total_length);
            let current_len = ptr::read_unaligned(len_ptr);
            ptr::write_unaligned(len_ptr, current_len + size as u32);
        }
    }
}

impl Drop for EventBuilder {
    fn drop(&mut self) {
        self.state = BuilderState::Closed;
    }
}

/// Estados por los que pasa un [`EventBuilder`], en orden.
///
/// Sirve para rechazar llamadas fuera de secuencia (p. ej. payload antes que cabecera).
#[derive(PartialEq, PartialOrd, Ord, Eq)]
enum BuilderState {
    Ready,
    HeaderWritten,
    PayloadWritten,
    TailWritten,
    Closed,
}
