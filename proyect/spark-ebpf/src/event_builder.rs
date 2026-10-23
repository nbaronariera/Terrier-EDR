use core::fmt;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, generated::bpf_ktime_get_ns},
    maps::{ring_buf::RingBufEntry, RingBuf},
};
use commons::event_wire::{
    EventKind, RawEventHeader, RawEventPayload, RawFilePayload, RawNetPayload, RawProcessPayload,
};

pub const MAX_EVENT_SIZE: usize = 1024 * 2;
pub const RING_BUFFER_SIZE: usize = 8 * 1024 * 1024;
pub const HEADER_SZ: usize = size_of::<RawEventHeader>();
pub const PAYLOAD_SZ: usize = size_of::<RawProcessPayload>();
pub const NET_SZ: usize = size_of::<RawNetPayload>();
pub const FILE_SZ: usize = size_of::<RawFilePayload>();

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
    reserved_memory: Option<RingBufEntry<[u8; MAX_EVENT_SIZE]>>,
    state: BuilderState,
    start_ptr: *mut u8,
    ptr: *mut u8,
}

impl EventBuilder {
    pub fn new(ringbuf: &RingBuf) -> Result<Self, BuilderError> {
        match ringbuf.reserve::<[u8; MAX_EVENT_SIZE]>(0) {
            Some(mut memory) => {
                let ptr = (*memory).as_mut_ptr() as *mut u8;
                Ok(Self {
                    state: BuilderState::Ready,
                    start_ptr: ptr,
                    ptr,
                    reserved_memory: Some(memory),
                })
            }
            None => Err(BuilderError::ReserveFailed),
        }
    }

    pub fn write_header(&mut self, event_type: EventKind) -> Result<&mut Self, BuilderError> {
        if self.state != BuilderState::Ready {
            return Err(BuilderError::InvalidState);
        }

        if self.reserved_memory.is_none() {
            return Err(BuilderError::MemoryLost);
        }

        let header = RawEventHeader {
            event_type: event_type as u8,
            total_length: HEADER_SZ as u32,
            timestamp: unsafe { bpf_ktime_get_ns() },
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
            uid: bpf_get_current_uid_gid() as u32,
        };

        unsafe {
            core::ptr::write_unaligned(self.ptr as *mut RawEventHeader, header);
            self.ptr = self.ptr.add(HEADER_SZ);
            self.state = BuilderState::HeaderWritten;
        }

        Ok(self)
    }

    pub fn write_payload(&mut self, payload: RawEventPayload) -> Result<&mut Self, BuilderError> {
        if self.state != BuilderState::HeaderWritten {
            return Err(BuilderError::InvalidState);
        }

        if self.reserved_memory.is_none() {
            return Err(BuilderError::MemoryLost);
        }

        unsafe {
            match payload {
                RawEventPayload::Process(p) => {
                    core::ptr::write_unaligned(self.ptr as *mut RawProcessPayload, p);
                    self.ptr = self.ptr.add(PAYLOAD_SZ);
                    self.add_total_length(PAYLOAD_SZ);
                }
                RawEventPayload::File(p) => {
                    core::ptr::write_unaligned(self.ptr as *mut RawFilePayload, p);
                    self.ptr = self.ptr.add(FILE_SZ);
                    self.add_total_length(FILE_SZ);
                }
                RawEventPayload::Net(p) => {
                    core::ptr::write_unaligned(self.ptr as *mut RawNetPayload, p);
                    self.ptr = self.ptr.add(NET_SZ);
                    self.add_total_length(NET_SZ);
                }
            }
            self.state = BuilderState::PayloadWritten;
        }
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
        self.state = BuilderState::TailWritten;

        Ok(self)
    }

    pub fn submit(&mut self) -> Result<(), BuilderError> {
        if self.state != BuilderState::TailWritten && self.state != BuilderState::PayloadWritten {
            return Err(BuilderError::InvalidState);
        }

        if let Some(mem) = self.reserved_memory.take() {
            mem.submit(0);
            self.state = BuilderState::Closed;
            Ok(())
        } else {
            Err(BuilderError::MemoryLost)
        }
    }

    pub fn discard(mut self) {
        if let Some(mem) = self.reserved_memory.take() {
            mem.discard(0);
            self.state = BuilderState::Closed;
        }
    }

    fn add_total_length(&mut self, size: usize) {
        if self.reserved_memory.is_some() {
            let header = self.start_ptr as *mut RawEventHeader;
            unsafe {
                let len_ptr = core::ptr::addr_of_mut!((*header).total_length);
                let current_len = core::ptr::read_unaligned(len_ptr);
                core::ptr::write_unaligned(len_ptr, current_len + size as u32);
            }
        }
    }
}

impl Drop for EventBuilder {
    fn drop(&mut self) {
        if let Some(mem) = self.reserved_memory.take() {
            mem.discard(0);
            self.state = BuilderState::Closed;
        }
    }
}

#[derive(PartialEq, PartialOrd, Ord, Eq)]
enum BuilderState {
    Ready,
    HeaderWritten,
    PayloadWritten,
    TailWritten,
    Closed,
}
