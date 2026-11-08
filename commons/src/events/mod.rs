//! Eventos de Terrier.
//!
//! - [`domain`]: tipos de dominio que comparten kernel y usuario. No usa memoria
//!   dinámica, así que no está detrás de ninguna feature.
//! - [`wire`]: formato binario del ring buffer (`#[repr(C)]`) y su parseo.
//! - [`user_space`]: eventos ya validados para espacio de usuario. Necesita
//!   `alloc`, así que va detrás de la feature `user`.

pub mod domain;
pub mod wire;

#[cfg(any(feature = "user", test))]
pub mod user_space;
