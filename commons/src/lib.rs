#![cfg_attr(not(test), no_std)]
pub mod event_wire;

#[cfg(any(feature = "user", test))]
pub mod events;

#[cfg(any(feature = "user", test))]
extern crate alloc;
