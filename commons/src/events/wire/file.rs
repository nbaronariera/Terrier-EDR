/// Payload binario de un evento de fichero.
///
/// Código de [`FileOperation`](crate::events::domain::FileOperation) como `u8`
/// e inodo del fichero. La ruta va en el tail del evento.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawFilePayload {
    pub operation: u8,
    pub inode: u64,
}
