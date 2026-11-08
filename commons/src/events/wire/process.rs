/// Payload binario de un evento de ejecución de proceso.
///
/// PID del proceso, PID del padre e inodo del binario. La ruta no va aquí
/// sino en el tail del evento.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawProcessPayload {
    pub process_id: u32,
    pub ancestor_id: u32,
    pub inode: u64,
}
