#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
use commons::events::domain::{NetOperation, NetResult};
use spark_ebpf::{
    event_assembly,
    vmlinux::{file, linux_binprm, sockaddr, socket},
};

/// Hook LSM que se dispara al ejecutar un binario (`execve`).
///
/// Emite un evento de proceso. Devuelve el código LSM (`0` = permitir).
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match try_bprm_check_security(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Hook LSM que se dispara al abrir un fichero.
///
/// Emite un evento de fichero. Devuelve el código LSM (`0` = permitir).
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_check_security(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Hook LSM que se dispara cuando un socket intenta conectarse.
///
/// Emite un evento de red. Devuelve el código LSM (`0` = permitir).
#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    match try_net_check_security(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Lógica de [`bprm_check_security`]: lee el `linux_binprm` y monta el evento de proceso.
///
/// Ignora errores de ensamblado y siempre permite la ejecución.
fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm: *const linux_binprm = ctx.arg(0);
    let _ = event_assembly::assemble_process(bprm);
    Ok(0)
}

/// Lógica de [`file_open_security`]: lee el `struct file` y monta el evento de fichero.
///
/// Ignora errores de ensamblado y siempre permite la apertura.
fn try_file_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let file: *const file = ctx.arg(0);
    let _ = event_assembly::assemble_file(file);
    Ok(0)
}

/// Lógica de [`net_check_security`]: lee socket, dirección y longitud y monta el evento de red.
///
/// Ignora errores de ensamblado y siempre permite la conexión.
fn try_net_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let socket: *const socket = ctx.arg(0);
    let socketadrr: *const sockaddr = ctx.arg(1);
    let addrlen: u32 = ctx.arg(2);
    let _ = event_assembly::assemble_net(
        socket,
        socketadrr,
        addrlen,
        NetOperation::Connect,
        NetResult::Success,
    );

    Ok(0)
}

/// Panic handler obligatorio en `no_std`. En eBPF nunca debería ejecutarse.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Licencia del programa eBPF; el kernel la exige GPL-compatible para ciertos helpers.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
