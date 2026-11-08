use core::ptr;

use aya_ebpf::{
     helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        generated::bpf_get_current_task,
    }, macros::map, maps::{PerCpuArray, RingBuf},
};
use commons::events::{
    domain::{FileOperation, NetOperation, NetResult},
    wire::{EventKind, RawFilePayload, RawNetIPv4Payload, RawNetIPv6Payload, RawProcessPayload},
};

use crate::{
    event_builder::{BuilderError, EventBuilder}, vmlinux::{file, linux_binprm, sock, sockaddr, sockaddr_in, sockaddr_in6, socket, task_struct},
};

const IPV4: u16 = 2;
const IPV6: u16 = 10;

/// Tamaño fijo (en bytes) que se reserva en el ring buffer para cada evento.
pub const MAX_EVENT_SIZE: usize = 1024 * 2;
/// Tamaño total (en bytes) del ring buffer compartido con espacio de usuario.
pub const RING_BUFFER_SIZE: usize = 8 * 1024 * 1024;

/// Ring buffer compartido por el que los programas eBPF envían los eventos a espacio de usuario.
#[map]
pub static mut EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUFFER_SIZE as u32, 0);

/// Scratchpad por CPU para extraer la longitud real de cada evento
#[map]
pub static mut SCRATCHPAD: PerCpuArray<[u8; MAX_EVENT_SIZE]> = PerCpuArray::with_max_entries(1, 0);

/// Errores al montar un evento completo en el ring buffer.
///
/// Engloba el fallo al reservar memoria, cualquier error del
/// [`EventBuilder`] y la falta de espacio para escribir el tail.
#[derive(Debug, Clone, Copy)]
pub enum AssembleError {
    ScratchpadAccessFailed,
    RingbufReserveFailed,
    Builder(BuilderError),
    TailSpaceMissing,
    UnexpectedProtocol,
}

impl From<BuilderError> for AssembleError {
    fn from(err: BuilderError) -> Self {
        AssembleError::Builder(err)
    }
}

/// Construye y envía al ring buffer un evento de ejecución de proceso.
///
/// A partir del `linux_binprm` del hook y de la `task_struct` actual lee el
/// PID, el PID del padre, el inodo del binario y su nombre (este último como tail).
/// Las lecturas del kernel que fallan se rellenan con `0`/vacío en vez de abortar.
pub fn assemble_process( bprm: *const linux_binprm) -> Result<(), AssembleError> {
    let mut builder =
        EventBuilder::new().ok_or(AssembleError::ScratchpadAccessFailed)?;
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

    builder.write_payload(commons::events::wire::RawEventPayload::Process(payload))?;

    let tail = builder.get_tail().ok_or(AssembleError::TailSpaceMissing)?;

    unsafe {
        let mut bytes_read = 0;
        if !name_ptr.is_null()
            && let Ok(read_str) = bpf_probe_read_kernel_str_bytes(name_ptr, tail)
        {
            bytes_read = read_str.len();
        }
        builder.end_tail_write(bytes_read as u32)?;
    }

    builder.submit()?;
    Ok(())
}

/// Construye y envía al ring buffer un evento de acceso a fichero.
///
/// Lee del `struct file` el inodo y el nombre del dentry (como tail). La
/// operación se marca siempre como [`FileOperation::Open`].
pub fn assemble_file( file: *const file) -> Result<(), AssembleError> {
    let mut builder =
        EventBuilder::new().ok_or(AssembleError::ScratchpadAccessFailed)?;
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

    let payload = commons::events::wire::RawEventPayload::File(RawFilePayload {
        operation: FileOperation::Open as u8,
        inode: inode_id,
    });

    builder.write_payload(payload)?;

    let tail = builder.get_tail().ok_or(AssembleError::TailSpaceMissing)?;

    unsafe {
        let mut bytes_read = 0;
        if !name_ptr.is_null()
            && let Ok(read_str) = bpf_probe_read_kernel_str_bytes(name_ptr, tail)
        {
            bytes_read = read_str.len();
        }
        builder.end_tail_write(bytes_read as u32)?;
    }

    builder.submit()?;
    Ok(())
}

/// Construye y envía al ring buffer un evento de red (en desarrollo).
///
/// Lee la familia del `sockaddr` (o del `sock` si no hay `sockaddr`) y,
/// según sea IPv4 o IPv6, vuelca origen, destino y protocolo en un
/// [`RawNetIPv4Payload`] o [`RawNetIPv6Payload`]. Según la operación, el
/// `sockaddr` se interpreta como origen (`Bind`) o destino (el resto).
/// Los puertos se pasan aquí a orden del host; las IPs se dejan en orden de
/// red. Este tipo de evento no lleva tail.
pub fn assemble_net(    socket: *const socket,
    sockaddr: *const sockaddr,
    addrlen: u32,
    operation: NetOperation,
    result: NetResult,
) -> Result<(), AssembleError> {
    if socket.is_null() && sockaddr.is_null() {
        return Ok(());
    }

    let sk: *const sock = unsafe {
        if socket.is_null() {
            ptr::null()
        } else {
            bpf_probe_read_kernel(ptr::addr_of!((*socket).sk)).unwrap_or(ptr::null_mut())
        }
    };

    let family: u16 = unsafe {
        if !sockaddr.is_null() && addrlen >= 2 {
            bpf_probe_read_kernel(ptr::addr_of!((*sockaddr).sa_family)).unwrap_or(0)
        } else if !sk.is_null() {
            bpf_probe_read_kernel(ptr::addr_of!((*sk).__sk_common.skc_family)).unwrap_or(0)
        } else {
            0
        }
    };

    if family != IPV4 && family != IPV6 {
        return Err(AssembleError::UnexpectedProtocol);
    }

    let protocol: u8 = unsafe {
        if !sk.is_null() {
            bpf_probe_read_kernel(ptr::addr_of!((*sk).sk_protocol)).unwrap_or(0) as u8
        } else {
            0
        }
    };

    // ¿`sockaddr` representa la dirección local (ej. en un Bind) o la remota (ej. en Connect)?
    let sockaddr_is_origin = matches!(operation, NetOperation::Bind);

    match family {
        IPV4 => {
            let mut origin_ip: u32 = 0;
            let mut origin_port: u16 = 0;
            let mut target_ip: u32 = 0;
            let mut target_port: u16 = 0;

            unsafe {
                if !sk.is_null() {
                    origin_ip = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk)
                            .__sk_common
                            .__bindgen_anon_1
                            .__bindgen_anon_1
                            .skc_rcv_saddr
                    ))
                    .unwrap_or(0);

                    origin_port = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk).__sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num
                    ))
                    .unwrap_or(0);

                    target_ip = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk)
                            .__sk_common
                            .__bindgen_anon_1
                            .__bindgen_anon_1
                            .skc_daddr
                    ))
                    .unwrap_or(0);

                    let dport_be = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk)
                            .__sk_common
                            .__bindgen_anon_3
                            .__bindgen_anon_1
                            .skc_dport
                    ))
                    .unwrap_or(0);
                    target_port = u16::from_be(dport_be);
                }

                if !sockaddr.is_null() && (addrlen as usize) >= core::mem::size_of::<sockaddr_in>()
                {
                    let sin = sockaddr as *const sockaddr_in;
                    let sa_ip =
                        bpf_probe_read_kernel(ptr::addr_of!((*sin).sin_addr.s_addr)).unwrap_or(0);
                    let sa_port_be =
                        bpf_probe_read_kernel(ptr::addr_of!((*sin).sin_port)).unwrap_or(0);
                    let sa_port = u16::from_be(sa_port_be);

                    if sockaddr_is_origin {
                        origin_ip = sa_ip;
                        origin_port = sa_port;
                    } else {
                        target_ip = sa_ip;
                        target_port = sa_port;
                    }
                }
            }

            let mut builder =
                EventBuilder::new().ok_or(AssembleError::ScratchpadAccessFailed)?;
            builder.write_header(EventKind::NetIPv4)?;

            let payload = commons::events::wire::RawEventPayload::NetIPv4(RawNetIPv4Payload {
                origin_ip,
                target_ip,
                origin_port,
                target_port,
                protocol,
                result: result.to_u8(),
                operation: operation.to_u8(),
            });

            builder.write_payload(payload)?;
            builder.submit()?;
            Ok(())
        }

        IPV6 => {
            let mut origin_ip: [u8; 16] = [0; 16];
            let mut origin_port: u16 = 0;
            let mut target_ip: [u8; 16] = [0; 16];
            let mut target_port: u16 = 0;

            unsafe {
                if !sk.is_null() {
                    origin_ip = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8
                    ))
                    .unwrap_or([0; 16]);

                    origin_port = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk).__sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num
                    ))
                    .unwrap_or(0);

                    target_ip = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk).__sk_common.skc_v6_daddr.in6_u.u6_addr8
                    ))
                    .unwrap_or([0; 16]);

                    let dport_be = bpf_probe_read_kernel(ptr::addr_of!(
                        (*sk)
                            .__sk_common
                            .__bindgen_anon_3
                            .__bindgen_anon_1
                            .skc_dport
                    ))
                    .unwrap_or(0);
                    target_port = u16::from_be(dport_be);
                }

                if !sockaddr.is_null() && (addrlen as usize) >= core::mem::size_of::<sockaddr_in6>()
                {
                    let sin6 = sockaddr as *const sockaddr_in6;
                    let sa_ip =
                        bpf_probe_read_kernel(ptr::addr_of!((*sin6).sin6_addr.in6_u.u6_addr8))
                            .unwrap_or([0; 16]);
                    let sa_port_be =
                        bpf_probe_read_kernel(ptr::addr_of!((*sin6).sin6_port)).unwrap_or(0);
                    let sa_port = u16::from_be(sa_port_be);

                    if sockaddr_is_origin {
                        origin_ip = sa_ip;
                        origin_port = sa_port;
                    } else {
                        target_ip = sa_ip;
                        target_port = sa_port;
                    }
                }
            }

            let mut builder =
                EventBuilder::new().ok_or(AssembleError::ScratchpadAccessFailed)?;
            builder.write_header(EventKind::NetIPv6)?;

            let payload = commons::events::wire::RawEventPayload::NetIPv6(RawNetIPv6Payload {
                origin_ip,
                target_ip,
                origin_port,
                target_port,
                protocol,
                result: result.to_u8(),
                operation: operation.to_u8(),
            });

            builder.write_payload(payload)?;
            builder.submit()?;
            Ok(())
        }

        _ => Ok(()),
    }
}
