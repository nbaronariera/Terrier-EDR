use alloc::string::String;

use crate::events::domain::FileOperation;

/// Evento de acceso a un fichero.
///
/// Guarda la ruta, el inodo y la [`FileOperation`] que se ha realizado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEvent {
    pub route: String,
    pub inode: u64,
    pub operation: FileOperation,
}
