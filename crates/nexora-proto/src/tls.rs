//! Caller-driven AWS-LC TLS 1.3 over memory BIOs, with no socket ownership.
mod certificate;
mod config;
mod context;
mod session;
mod state;

pub use config::{TlsClientConfig, TlsServerConfig};
pub use session::TlsSession;

use crate::{BytesMut, ProtoError, Result};

/// Application protocols supported by the TLS adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnProtocol {
    /// HTTP/1.1 (`http/1.1`).
    Http11,
    /// HTTP/2 (`h2`).
    Http2,
}
/// The local endpoint's handshake role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    /// Initiates TLS and verifies the server identity.
    Client,
    /// Accepts TLS using its configured identity.
    Server,
}
