use alloc::string::String;

/// Evento de ejecución de un proceso (hook `bprm_check_security`).
///
/// Guarda el PID del proceso, el de su padre, el inodo del binario
/// ejecutado y su ruta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessEvent {
    pub process: u32,
    pub ancestor: u32,
    pub inode: u64,
    pub route: String,
    //args: u32, TODO
}
