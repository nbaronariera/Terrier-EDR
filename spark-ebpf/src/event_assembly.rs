use core::ptr;

use aya_ebpf::{
    bindings::{sockaddr, socket},
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        generated::bpf_get_current_task,
    },
    maps::RingBuf,
};
use commons::event_wire::{EventKind, FileOperation, RawFilePayload, RawProcessPayload};

use crate::{
    event_builder::{BuilderError, EventBuilder},
    vmlinux::{file, linux_binprm, task_struct},
};

#[derive(Debug, Clone, Copy)]
pub enum AssembleError {
    RingbufReserveFailed,
    Builder(BuilderError),
    TailSpaceMissing,
}

impl From<BuilderError> for AssembleError {
    fn from(err: BuilderError) -> Self {
        AssembleError::Builder(err)
    }
}

pub fn assemble_process(ringbuf: &RingBuf, bprm: *const linux_binprm) -> Result<(), AssembleError> {
    let mut builder =
        EventBuilder::new(ringbuf).map_err(|_| AssembleError::RingbufReserveFailed)?;
    builder.write_header(EventKind::Process)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let user_pid = (pid_tgid >> 32) as u32;

    let mut parent_pid: u32 = 0;
    let mut inode_id: u64 = 0;
    let mut name_ptr: *const u8 = ptr::null();

    unsafe {
        let task = bpf_get_current_task() as *const task_struct;

        let real_parent =
            bpf_probe_read_kernel(ptr::addr_of!((*task).real_parent)).unwrap_or(ptr::null_mut());

        if !real_parent.is_null() {
            parent_pid =
                bpf_probe_read_kernel(ptr::addr_of!((*real_parent).tgid)).unwrap_or(0) as u32;
        }

        let file_ptr =
            bpf_probe_read_kernel(ptr::addr_of!((*bprm).file)).unwrap_or(ptr::null_mut());

        if !file_ptr.is_null() {
            let inode_ptr = bpf_probe_read_kernel(ptr::addr_of!((*file_ptr).f_inode))
                .unwrap_or(ptr::null_mut());
            if !inode_ptr.is_null() {
                inode_id =
                    bpf_probe_read_kernel(ptr::addr_of!((*inode_ptr).i_ino)).unwrap_or(0) as u64;
            }

            let dentry_ptr =
                bpf_probe_read_kernel(ptr::addr_of!((*file_ptr).__bindgen_anon_1.f_path.dentry))
                    .unwrap_or(ptr::null_mut());
            if !dentry_ptr.is_null() {
                name_ptr = bpf_probe_read_kernel(ptr::addr_of!(
                    (*dentry_ptr).__bindgen_anon_1.d_name.name
                ))
                .unwrap_or(ptr::null());
            }
        }
    }

    let payload = RawProcessPayload {
        process_id: user_pid,
        ancestor_id: parent_pid,
        inode: inode_id,
    };

    builder.write_payload(commons::event_wire::RawEventPayload::Process(payload))?;

    let tail = builder.get_tail().ok_or(AssembleError::TailSpaceMissing)?;

    unsafe {
        let mut bytes_read = 0;
        if !name_ptr.is_null() {
            if let Ok(read_str) = bpf_probe_read_kernel_str_bytes(name_ptr, tail) {
                bytes_read = read_str.len();
            }
        }
        builder.end_tail_write(bytes_read as u32)?;
    }

    builder.submit()?;
    Ok(())
}

pub fn assemble_file(ringbuf: &RingBuf, file: *const file) -> Result<(), AssembleError> {
    let mut builder =
        EventBuilder::new(ringbuf).map_err(|_| AssembleError::RingbufReserveFailed)?;
    builder.write_header(EventKind::File)?;

    let mut inode_id: u64 = 0;
    let mut name_ptr: *const u8 = ptr::null();

    unsafe {
        let inode_ptr =
            bpf_probe_read_kernel(ptr::addr_of!((*file).f_inode)).unwrap_or(ptr::null_mut());
        if !inode_ptr.is_null() {
            inode_id = bpf_probe_read_kernel(ptr::addr_of!((*inode_ptr).i_ino)).unwrap_or(0) as u64;
        }

        let dentry_ptr =
            bpf_probe_read_kernel(ptr::addr_of!((*file).__bindgen_anon_1.f_path.dentry))
                .unwrap_or(ptr::null_mut());
        if !dentry_ptr.is_null() {
            name_ptr =
                bpf_probe_read_kernel(ptr::addr_of!((*dentry_ptr).__bindgen_anon_1.d_name.name))
                    .unwrap_or(ptr::null());
        }
    }

    let payload = commons::event_wire::RawEventPayload::File(RawFilePayload {
        operation: FileOperation::Open as u8,
        inode: inode_id,
    });

    builder.write_payload(payload)?;

    let tail = builder.get_tail().ok_or(AssembleError::TailSpaceMissing)?;

    unsafe {
        let mut bytes_read = 0;
        if !name_ptr.is_null() {
            if let Ok(read_str) = bpf_probe_read_kernel_str_bytes(name_ptr, tail) {
                bytes_read = read_str.len();
            }
        }
        builder.end_tail_write(bytes_read as u32)?;
    }

    builder.submit()?;
    Ok(())
}

pub fn assemble_net(
    ringbuf: &RingBuf,
    socket: *const socket,
    sockaddr: *const sockaddr,
    addrlen: u32,
) -> Result<(), u32> {
    Ok(())
}
