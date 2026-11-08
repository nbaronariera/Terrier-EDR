use core::net::{Ipv4Addr, Ipv6Addr};

use strum_macros::FromRepr;

/// Tipo de operación realizada sobre un fichero.
///
/// Se transmite como `u8` en [`RawFilePayload::operation`](crate::events::wire::RawFilePayload::operation)
/// y se recupera con `FileOperation::from_repr`.
#[derive(Debug, PartialEq, Eq, FromRepr, Clone, Copy)]
#[repr(u8)]
pub enum FileOperation {
    Open = 0,
    Write = 1,
    Read = 2,
    Rename = 3,
    Move = 4,
    Link = 5,
    Unlink = 6,
}

// NOTA: documentación revisada por IA (Claude), regla 2 de CLAUDE.md.
/// Dirección de red (IP + puerto) de un extremo de la conexión.
///
/// Ya está en espacio de usuario: `port` va en orden del host y `ip` es un
/// [`NetAddressProtocol`], que no expone orden de bytes. Las conversiones
/// desde el formato de cable se hacen en los constructores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetAddress {
    pub ip: NetAddressProtocol,
    pub port: u16,
}

/// IP de un extremo de la conexión, IPv4 o IPv6.
///
/// Envuelve los tipos de [`core::net`], que guardan la dirección como
/// octetos; `to_bits()` devuelve el valor numérico en orden del host.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NetAddressProtocol {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
}

impl NetAddress {
    /// Construye una dirección IPv4 a partir de la IP en Big Endian (del kernel)
    /// y el puerto ya normalizado a Host Endian.
    pub const fn new_ipv4(ip_be: u32, port: u16) -> Self {
        Self {
            ip: NetAddressProtocol::create_ipv4(ip_be),
            port,
        }
    }

    /// Construye una dirección IPv6 a partir de los 16 octetos del kernel
    /// y el puerto ya normalizado a Host Endian.
    pub const fn new_ipv6_bytes(ip_be: [u8; 16], port: u16) -> Self {
        Self {
            ip: NetAddressProtocol::create_ipv6_bytes(ip_be),
            port,
        }
    }
}

impl NetAddressProtocol {
    /// Recibe un `u32` en Big Endian (tal cual sale del kernel)
    pub const fn create_ipv4(direction_be: u32) -> Self {
        Self::IPv4(Ipv4Addr::from_bits(u32::from_be(direction_be)))
    }

    /// Recibe un `[u8; 16]` en Big Endian (tal cual sale de `in6_addr` en el kernel)
    pub const fn create_ipv6_bytes(direction_be: [u8; 16]) -> Self {
        Self::IPv6(Ipv6Addr::from_octets(direction_be))
    }

    /// Recibe un `u128` en Big Endian
    pub const fn create_ipv6(direction_be: u128) -> Self {
        Self::IPv6(Ipv6Addr::from_bits(u128::from_be(direction_be)))
    }
}

/// Resultado de una operación de red.
///
/// `0` significa éxito; cualquier otro valor se conserva como código de
/// error dentro de `Failed`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NetResult {
    Success,
    Failed(u8),
}

impl NetResult {
    /// Interpreta un código numérico como [`NetResult`].
    ///
    /// `0` → `Success`; cualquier otro valor → `Failed(valor)`. Nunca falla.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Success,
            err_code => Self::Failed(err_code),
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            // Si alguien pasa Failed(0) por error, evitamos que se convierta en Success(0)
            Self::Failed(0) => u8::MAX,
            Self::Failed(code) => code,
        }
    }

    /// Convierte el retorno de una función del kernel (0 o -errno) en `u8` para el payload
    pub const fn raw_from_kernel_ret(ret: i32) -> u8 {
        if ret == 0 {
            0
        } else if ret < 0 {
            (-ret) as u8
        } else {
            ret as u8
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NetOperation {
    Connect,
    Bind,
    UndefinedOperation(u8),
}

impl NetOperation {
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Connect => 1,
            Self::Bind => 2,
            Self::UndefinedOperation(v) => v,
        }
    }

    pub const fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Connect,
            2 => Self::Bind,
            other => Self::UndefinedOperation(other),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NetProtocol {
    ICMP,
    TCP,
    UDP,
    UndefinedProtocol(u8),
}

impl NetProtocol {
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::ICMP => 1,
            Self::TCP => 6,
            Self::UDP => 17,
            Self::UndefinedProtocol(v) => v,
        }
    }

    pub const fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::ICMP,
            6 => Self::TCP,
            17 => Self::UDP,
            other => Self::UndefinedProtocol(other),
        }
    }
}

// NOTA: tests generados/asistidos por IA (Claude), regla 2 de CLAUDE.md.
#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn new_ipv4_converts_ip_from_network_order_and_keeps_port() {
        let addr = NetAddress::new_ipv4(0xC0A80001u32.to_be(), 0x1234);
        assert_eq!(
            addr.ip,
            NetAddressProtocol::IPv4(Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(addr.port, 0x1234);
    }

    #[test]
    fn new_ipv6_bytes_reads_octets_in_network_order() {
        // 2001:db8::1 tal cual aparece en `in6_addr`.
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        octets[2] = 0x0d;
        octets[3] = 0xb8;
        octets[15] = 0x01;

        let addr = NetAddress::new_ipv6_bytes(octets, 0xABCD);
        assert_eq!(
            addr.ip,
            NetAddressProtocol::IPv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(addr.port, 0xABCD);
    }

    #[test]
    fn net_operation_roundtrip() {
        for op in [
            NetOperation::Connect,
            NetOperation::Bind,
            NetOperation::UndefinedOperation(200),
        ] {
            assert_eq!(NetOperation::from_u8(op.to_u8()), op);
        }
    }

    #[test]
    fn net_protocol_roundtrip() {
        for proto in [
            NetProtocol::ICMP,
            NetProtocol::TCP,
            NetProtocol::UDP,
            NetProtocol::UndefinedProtocol(47),
        ] {
            assert_eq!(NetProtocol::from_u8(proto.to_u8()), proto);
        }
    }

    #[test]
    fn net_result_roundtrip_and_failed_zero_is_not_success() {
        assert_eq!(NetResult::from_u8(NetResult::Success.to_u8()), NetResult::Success);
        assert_eq!(
            NetResult::from_u8(NetResult::Failed(5).to_u8()),
            NetResult::Failed(5)
        );
        assert_ne!(NetResult::Failed(0).to_u8(), NetResult::Success.to_u8());
    }

    #[test]
    fn raw_from_kernel_ret_maps_negative_errno() {
        assert_eq!(NetResult::raw_from_kernel_ret(0), 0);
        // -ECONNREFUSED (111)
        assert_eq!(NetResult::raw_from_kernel_ret(-111), 111);
    }
}
