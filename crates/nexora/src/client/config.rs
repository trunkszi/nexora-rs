//! Independent request, response, and TLS identity policies for the HTTP client.

use std::time::Duration;

use liburing::{Proactor, SubsystemId};
use nexora_proto::TlsClientConfig;

use super::HttpClient;
use crate::{PoolConfig, Result};

/// Client-wide limits for connections, redirects, bodies, and DNS.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub pool: PoolConfig,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_redirects: usize,
    pub follow_redirects: bool,
    pub max_header_list_size: usize,
    /// Maximum decoded response body size; zero permits only empty bodies.
    pub max_body_size: usize,
    /// Maximum upload body size, independently of the response limit.
    pub max_request_body_size: usize,
    pub prefer_http2: bool,
    pub http2_prior_knowledge: bool,
    pub tls_config: Option<TlsClientConfig>,
    /// TLS SNI and certificate name override; the URI and HTTP authority are retained.
    pub tls_server_name: Option<String>,
    pub dns_servers_csv: Option<String>,
    pub net_subsystem: SubsystemId,
    pub dns_subsystem: SubsystemId,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            pool: PoolConfig::default(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_redirects: 5,
            follow_redirects: true,
            max_header_list_size: 16 * 1024,
            max_body_size: 16 * 1024 * 1024,
            max_request_body_size: usize::MAX,
            prefer_http2: true,
            http2_prior_knowledge: false,
            tls_config: None,
            tls_server_name: None,
            dns_servers_csv: None,
            net_subsystem: SubsystemId::new_unchecked(1),
            dns_subsystem: SubsystemId::new_unchecked(2),
        }
    }
}

/// Builder for [`HttpClient`]; the configuration is a public struct, so callers
/// may also construct [`ClientConfig`] directly.
#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    config: ClientConfig,
}

impl ClientBuilder {
    /// Creates a builder over the default configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds the client, creating and arming its DNS resolver.
    ///
    /// # Errors
    /// Returns a DNS configuration or proactor submission error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn build(self, proactor: &mut Proactor) -> Result<HttpClient> {
        HttpClient::new(proactor, self.config)
    }
}
