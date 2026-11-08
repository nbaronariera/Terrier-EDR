// NOTA: estructura de módulos hecha por IA (Claude). Ver `events/mod.rs`.

//! Formato de cable: lo que el lado eBPF escribe en el ring buffer y el lado
//! de usuario lee y parsea.
//!
//! Los submódulos son privados y todo se re-exporta aquí, así que los tipos se
//! importan como `commons::events::wire::RawNetPayload`.

mod common;
mod file;
mod net;
mod process;

pub use common::*;
pub use file::*;
pub use net::*;
pub use process::*;
