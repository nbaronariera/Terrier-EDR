#![cfg_attr(not(test), no_std)]
pub mod events;

#[cfg(any(feature = "user", test))]
extern crate alloc;
