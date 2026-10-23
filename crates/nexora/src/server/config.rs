//! Listener limits and the builder that binds [`super::HttpServer`].

use std::net::SocketAddr;

use liburing::{Proactor, SubsystemId};

use super::{driver::HttpServer, service::HttpService};
use crate::{Result, TlsServerConfig};

/// Limits, TLS identity, and the proactor subsystem used by [`HttpServer`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Maximum HTTP/1 header block size, in bytes.
    pub max_header_list_size: usize,
    /// Maximum request body size, in bytes. Larger bodies become `413`.
    pub max_body_size: usize,
    /// When set, a leading `0x16` byte starts a TLS 1.3 server handshake.
    pub tls: Option<TlsServerConfig>,
    /// Completion routing id. Defaults to `3` so client ids `1` and `2` stay free.
    pub net_subsystem: SubsystemId,
    /// `listen` backlog. Non-positive values use `128`.
    pub backlog: i32,
    /// Fixed receive and transmit buffer size for each accepted socket.
    pub io_buffer_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_header_list_size: 16 * 1024,
            max_body_size: 16 * 1024 * 1024,
            tls: None,
            net_subsystem: SubsystemId::new_unchecked(3),
            backlog: 128,
            io_buffer_size: 16 * 1024,
        }
    }
}

/// Builds an [`HttpServer`] from a service and a [`ServerConfig`].
pub struct ServerBuilder<S> {
    service: S,
    config: ServerConfig,
}

impl<S> ServerBuilder<S> {
    /// Creates a builder that uses [`ServerConfig::default`].
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn new(service: S) -> Self {
        Self {
            service,
            config: ServerConfig::default(),
        }
    }

    /// Replaces the server configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }
}

impl<S: HttpService + 'static> ServerBuilder<S> {
    /// Binds `addr` and registers the server on the proactor.
    ///
    /// # Errors
    /// Returns a socket, bind, listen, buffer, or proactor registration error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn bind(self, proactor: &mut Proactor, addr: SocketAddr) -> Result<HttpServer<S>> {
        HttpServer::bind(proactor, addr, self.config, self.service)
    }
}
