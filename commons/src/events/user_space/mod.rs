// NOTA: estructura de módulos hecha por IA (Claude). Ver `events/mod.rs`.

//! Eventos ya validados y tipados para espacio de usuario.
//!
//! Los submódulos son privados y todo se re-exporta aquí, así que los tipos se
//! importan como `commons::events::user_space::Event`.

mod common;
mod file;
mod net;
mod process;

pub use common::*;
pub use file::*;
pub use net::*;
pub use process::*;
