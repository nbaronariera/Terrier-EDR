#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{sockaddr, socket},
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
};
use spark_ebpf::{
    event_assembly,
    event_builder::RING_BUFFER_SIZE,
    vmlinux::{file, linux_binprm},
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUFFER_SIZE as u32, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match try_bprm_check_security(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "file_open")]
pub fn file_open_security(ctx: LsmContext) -> i32 {
    match try_file_check_security(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "socket_connect")]
pub fn net_check_security(ctx: LsmContext) -> i32 {
    match try_net_check_security(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm: *const linux_binprm = ctx.arg(0);
    let _ = event_assembly::assemble_process(&EVENTS, bprm);
    Ok(0)
}

fn try_file_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let file: *const file = ctx.arg(0);
    let _ = event_assembly::assemble_file(&EVENTS, file);
    Ok(0)
}

fn try_net_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let socket: *const socket = ctx.arg(0);
    let socketadrr: *const sockaddr = ctx.arg(1);
    let addrlen: u32 = ctx.arg(2);
    let _ = event_assembly::assemble_net(&EVENTS, socket, socketadrr, addrlen);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
