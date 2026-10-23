#![no_std]

// This file exists to enable the library target.
pub mod event_assembly;
pub mod event_builder;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(unnecessary_transmutes)]
#[allow(unsafe_op_in_unsafe_fn)]
pub mod vmlinux;
