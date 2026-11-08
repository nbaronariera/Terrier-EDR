use crate::events::domain::{NetAddress, NetOperation, NetProtocol, NetResult};

// NOTA: documentación revisada por IA (Claude), regla 2 de CLAUDE.md.
/// Evento de actividad de red.
///
/// Describe una operación de red: dirección de origen y destino (cada una
/// opcional), protocolo, resultado y tipo de operación (connect, bind...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetEvent {
    pub origin: Option<NetAddress>,
    pub target: Option<NetAddress>,
    pub protocol: NetProtocol,
    pub result: NetResult,
    pub operation: NetOperation,
}
