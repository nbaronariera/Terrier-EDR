// NOTA: documentación revisada por IA (Claude), regla 2 de CLAUDE.md.
/// Payload binario de un evento de red IPv4 ([`EventKind::NetIPv4`](super::EventKind::NetIPv4)).
///
/// Orden de bytes (regla mixta, a propósito):
/// - IPs: en orden de red (big endian), tal cual las da el kernel. Se pasan
///   a tipo de dominio en espacio de usuario.
/// - Puertos: ya en orden del host. El lado eBPF los convierte al leerlos.
///
/// Protocolo, operación y resultado van como `u8` y se traducen a enums en
/// el lado de usuario.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawNetIPv4Payload {
    pub origin_ip: u32,
    pub target_ip: u32,
    pub origin_port: u16,
    pub target_port: u16,
    pub protocol: u8,
    pub operation: u8,
    pub result: u8,
}

/// Payload binario de un evento de red IPv6 ([`EventKind::NetIPv6`](super::EventKind::NetIPv6)).
///
/// Mismo orden de bytes que [`RawNetIPv4Payload`]: las IPs son los 16
/// octetos de `in6_addr` en orden de red y los puertos van ya en orden del host.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawNetIPv6Payload {
    pub origin_ip: [u8; 16],
    pub target_ip: [u8; 16],
    pub origin_port: u16,
    pub target_port: u16,
    pub protocol: u8,
    pub operation: u8,
    pub result: u8,
}
