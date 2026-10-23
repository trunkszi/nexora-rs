//! Origin start-up, dual-stack DNS bookkeeping, and connection opening.
//!
//! Lookup answers arrive through the inbox; one address family failing never
//! fails the origin while the other family can still produce an address.

use std::time::Instant;

use liburing::Proactor;
use nexora_proto::{Http2Config, Http2Connection, Http2Role, Http2Settings};

use super::{ClientConfig, HttpClient, TimerKind};
use crate::{
    error::{Error, Result},
    inbox::{AddressFamily, DnsResolution},
    pool::{
        ConnKind, Connection, ConnectionLimits, OriginKey, OriginState, close_raw, open_socket,
    },
};

/// What one DNS answer means for its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DnsSettlement {
    /// Every address family answered and at least one produced addresses.
    Usable,
    /// Every address family answered without producing an address.
    Failed(String),
}

/// Result of recording one answer for an origin's dual-stack lookup.
pub(super) struct DnsStep {
    /// This answer carried at least one address.
    pub(super) usable: bool,
    /// Set once every address family has answered.
    pub(super) settlement: Option<DnsSettlement>,
}

/// Dual-stack lookup bookkeeping for one origin.
///
/// Both families are queried together, so the origin fails only after every
/// family has answered without an address. Answers are keyed by family because
/// two origins that share a host and port (only the scheme differs) receive
/// each other's results through the same inbox.
pub(super) struct DnsProgress {
    ipv4: bool,
    ipv6: bool,
    resolved: bool,
    failure: Option<String>,
}

impl DnsProgress {
    /// Starts a lookup with both address families outstanding.
    pub(super) fn new() -> Self {
        Self {
            ipv4: false,
            ipv6: false,
            resolved: false,
            failure: None,
        }
    }

    /// Reports whether at least one family is still unresolved.
    pub(super) fn is_pending(&self) -> bool {
        !(self.ipv4 && self.ipv6)
    }

    /// Records one family's answer and reports whether the origin is settled.
    pub(super) fn record(&mut self, resolution: &DnsResolution) -> DnsStep {
        let answered = match resolution.family {
            AddressFamily::Ipv4 => &mut self.ipv4,
            AddressFamily::Ipv6 => &mut self.ipv6,
        };
        if *answered {
            // A duplicate of a recorded family must not settle the lookup
            // while the other family is still outstanding.
            return DnsStep {
                usable: false,
                settlement: None,
            };
        }
        *answered = true;
        if resolution.is_usable() {
            self.resolved = true;
        } else {
            let text = match resolution.error.as_deref() {
                Some(text) if !text.is_empty() => text.to_string(),
                _ => String::from("lookup returned no addresses"),
            };
            self.failure = Some(match self.failure.take() {
                Some(previous) => format!("{previous}; {text}"),
                None => text,
            });
        }
        let settlement = (!self.is_pending()).then(|| {
            if self.resolved {
                DnsSettlement::Usable
            } else {
                DnsSettlement::Failed(
                    self.failure
                        .clone()
                        .unwrap_or_else(|| String::from("no address records")),
                )
            }
        });
        DnsStep {
            usable: resolution.is_usable(),
            settlement,
        }
    }
}

impl HttpClient {
    /// Starts a connection for `key`, consulting overrides, an IP literal, and
    /// the TTL cache before submitting a DNS query.
    ///
    /// # Errors
    /// Returns a socket, c-ares, or proactor submission error.
    pub(super) fn start_origin(&mut self, proactor: &mut Proactor, key: &OriginKey) -> Result<()> {
        if let Some(addrs) =
            self.resolver
                .lookup_static_or_cache(&key.host, key.port, Instant::now())
        {
            self.origin_ips.insert(key.clone(), addrs.clone());
            self.pool.entry(key).candidate_ips = addrs.into();
            self.pool.set_state(key, OriginState::Connecting);
            return self.open_connection(proactor, key);
        }
        if self.pool.begin_dns(key) {
            self.start_dns(proactor, key)?;
        }
        Ok(())
    }

    /// Submits the `A` and `AAAA` queries for `key`.
    ///
    /// # Errors
    /// Returns a resolver submission error; the origin is returned to
    /// [`OriginState::Idle`] so a later turn can retry the lookup.
    fn start_dns(&mut self, proactor: &mut Proactor, key: &OriginKey) -> Result<()> {
        match self
            .resolver
            .start_query(proactor, &key.host, key.port, &self.inbox)
        {
            Ok(handles) => {
                self.pool.set_query_handles(key, handles);
                drop(self.dns.insert(key.clone(), DnsProgress::new()));
                Ok(())
            }
            Err(error) => {
                drop(self.dns.remove(key));
                self.pool.set_state(key, OriginState::Idle);
                Err(error)
            }
        }
    }

    /// Applies one lookup answer to every origin waiting on that host and port.
    pub(super) fn apply_dns(&mut self, proactor: &mut Proactor, resolution: DnsResolution) {
        let keys: Vec<OriginKey> = self
            .dns
            .keys()
            .filter(|key| {
                key.port == resolution.port && key.host.eq_ignore_ascii_case(&resolution.host)
            })
            .cloned()
            .collect();
        for key in keys {
            self.apply_origin_dns(proactor, &key, &resolution);
        }
    }

    /// Records one answer for `key`, caches usable addresses, and opens a
    /// connection when the origin has none in progress.
    fn apply_origin_dns(
        &mut self,
        proactor: &mut Proactor,
        key: &OriginKey,
        resolution: &DnsResolution,
    ) {
        let Some(progress) = self.dns.get_mut(key) else {
            return;
        };
        let step = progress.record(resolution);
        if step.usable {
            self.resolver.store_cache(
                &resolution.host,
                resolution.port,
                resolution.addrs.clone(),
                resolution.ttl,
                Instant::now(),
            );
            self.merge_addresses(key, &resolution.addrs);
            let state = self.pool.state(key).unwrap_or(OriginState::Idle);
            let open = state == OriginState::ResolvingDns
                || (state == OriginState::Connecting && !self.has_connecting(key));
            if open {
                self.pool.set_state(key, OriginState::Connecting);
                if self.open_connection(proactor, key).is_err() {
                    self.reset_origin_state(key);
                }
            }
        }
        match step.settlement {
            Some(DnsSettlement::Usable) => drop(self.dns.remove(key)),
            Some(DnsSettlement::Failed(reason)) => self.fail_origin(
                key,
                Error::DnsResolutionFailed {
                    host: key.host.clone(),
                    reason,
                },
            ),
            None => {}
        }
    }

    /// Adds addresses to both the origin's retained set and its pending
    /// candidate queue, keeping the first occurrence of each address.
    fn merge_addresses(&mut self, key: &OriginKey, addrs: &[std::net::SocketAddr]) {
        let retained = self.origin_ips.entry(key.clone()).or_default();
        for addr in addrs {
            if !retained.contains(addr) {
                retained.push(*addr);
            }
        }
        let candidates = &mut self.pool.entry(key).candidate_ips;
        for addr in addrs {
            if !candidates.contains(addr) {
                candidates.push_back(*addr);
            }
        }
    }

    /// Fails an origin's waiters, unless a working connection or an
    /// outstanding address family can still serve them.
    pub(super) fn fail_origin(&mut self, key: &OriginKey, error: Error) {
        drop(self.dns.remove(key));
        let handles = self.pool.take_query_handles(key);
        self.resolver.cancel_queries(&handles);
        if let Some(state) = self.live_state(key) {
            // A sibling connection still serves this origin; failing the
            // waiters would report an error for an origin that is usable.
            self.pool.set_state(key, state);
            return;
        }
        self.pool.set_state(key, OriginState::Idle);
        let waiters = self.pool.take_waiters(key);
        let mut pending = Some(error);
        for id in waiters {
            let outcome = pending
                .take()
                .unwrap_or_else(|| Error::DnsResolutionFailed {
                    host: key.host.clone(),
                    reason: String::from("no usable address"),
                });
            self.complete(id, Err(outcome));
        }
    }

    /// Returns a live connection's protocol state for `key`, ignoring
    /// connections that are closing or draining under `GOAWAY`.
    pub(super) fn live_state(&self, key: &OriginKey) -> Option<OriginState> {
        let mut http1 = false;
        let mut http2 = false;
        for conn in self.conns.values().filter(|conn| {
            &conn.key == key && !conn.want_close && !self.draining.contains(&conn.id)
        }) {
            match conn.kind {
                ConnKind::Http2 => http2 = true,
                ConnKind::Http1 => http1 = true,
                _ => {}
            }
        }
        if http2 {
            Some(OriginState::ReadyHttp2)
        } else if http1 {
            Some(OriginState::ReadyHttp1)
        } else {
            None
        }
    }

    /// Reports whether a connect or TLS handshake is still in progress.
    pub(super) fn has_connecting(&self, key: &OriginKey) -> bool {
        self.conns.values().any(|conn| {
            &conn.key == key
                && !conn.want_close
                && matches!(conn.kind, ConnKind::Connecting | ConnKind::Handshaking)
        })
    }

    /// Returns an origin whose last connection attempt failed to a routable
    /// state, so its queued waiters retry instead of waiting forever.
    fn reset_origin_state(&mut self, key: &OriginKey) {
        let state = self.live_state(key).unwrap_or(OriginState::Idle);
        self.pool.set_state(key, state);
    }

    /// Opens one connection to the origin's next candidate address.
    ///
    /// One candidate per call lets parallel HTTP/1.1 fan-out and multi-address
    /// failover stay bounded by the pool limits.
    ///
    /// # Errors
    /// Returns the socket creation or proactor submission error.
    pub(super) fn open_connection(
        &mut self,
        proactor: &mut Proactor,
        key: &OriginKey,
    ) -> Result<()> {
        let parallel = matches!(
            self.pool.state(key),
            Some(OriginState::ReadyHttp1 | OriginState::ReadyHttp2)
        );
        if parallel
            && self.pool.entry(key).candidate_ips.is_empty()
            && let Some(addrs) = self.origin_ips.get(key).cloned()
        {
            self.pool.entry(key).candidate_ips = addrs.into();
        }
        let Some(addr) = self.pool.entry(key).candidate_ips.pop_front() else {
            self.fail_origin(
                key,
                Error::DnsResolutionFailed {
                    host: key.host.clone(),
                    reason: String::from("no usable address"),
                },
            );
            return Ok(());
        };
        let fd = match open_socket(&addr) {
            Ok(fd) => fd,
            Err(error) => {
                self.reset_origin_state(key);
                return Err(error);
            }
        };
        let id = self.next_conn;
        self.next_conn = self.next_conn.saturating_add(1);
        if !self.pool.add_connection(key, id, Instant::now()) {
            close_raw(fd);
            self.reset_origin_state(key);
            return Ok(());
        }
        let http2 = http2_config(&self.config);
        let limits = ConnectionLimits {
            max_header_list_size: self.config.max_header_list_size,
            max_body_size: self.config.max_body_size,
            max_request_body_size: self.config.max_request_body_size,
            http2_prior_knowledge: self.config.http2_prior_knowledge,
        };
        let mut conn = Connection::new(id, key.clone(), fd, addr, limits);
        if conn.http2.is_some() {
            // `Connection::new` builds HTTP/2 state from shared defaults;
            // replace it so the client-wide header limit applies.
            conn.http2 = Some(Http2Connection::new(Http2Role::Client, http2));
        }
        if let Err(error) = conn.flush(proactor, self.config.net_subsystem, &mut self.ops) {
            // The connect stage either stages its SQE or returns before doing
            // so; dropping `conn` then closes the untransferred descriptor.
            self.pool.remove_connection(key, id);
            self.reset_origin_state(key);
            return Err(error);
        }
        let registered = self.pool.connection_count(key);
        self.conns.insert(id, conn);
        if registered <= 1 {
            self.pool.set_state(key, OriginState::Connecting);
        }
        // The connection is already staged on the ring; a missing deadline
        // removes the connect timeout but must not discard the connection.
        drop(self.arm_timer(
            proactor,
            self.config.connect_timeout,
            TimerKind::Connect(id),
            None,
        ));
        Ok(())
    }
}

/// Builds the HTTP/2 configuration applied to every client connection.
pub(super) fn http2_config(config: &ClientConfig) -> Http2Config {
    Http2Config {
        local_settings: Http2Settings {
            enable_push: false,
            max_header_list_size: u32::try_from(config.max_header_list_size).unwrap_or(u32::MAX),
            ..Http2Settings::default()
        },
        max_body_size: config.max_body_size,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use super::*;

    fn one_address() -> Vec<SocketAddr> {
        vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            443,
        )]
    }

    #[test]
    fn one_family_failing_does_not_settle_the_origin() {
        let mut progress = DnsProgress::new();
        let failure = DnsResolution::failure("example.test", 443, AddressFamily::Ipv4, "timeout");
        let step = progress.record(&failure);
        assert!(!step.usable);
        assert!(step.settlement.is_none());
        assert!(progress.is_pending());
    }

    #[test]
    fn both_families_failing_settle_with_both_reasons() {
        let mut progress = DnsProgress::new();
        let ipv4 = DnsResolution::failure("example.test", 443, AddressFamily::Ipv4, "v4 timeout");
        let ipv6 = DnsResolution::failure("example.test", 443, AddressFamily::Ipv6, "v6 nodata");
        assert!(progress.record(&ipv4).settlement.is_none());
        let step = progress.record(&ipv6);
        match step.settlement {
            Some(DnsSettlement::Failed(reason)) => {
                assert!(reason.contains("v4 timeout"), "reason: {reason}");
                assert!(reason.contains("v6 nodata"), "reason: {reason}");
            }
            other => assert!(other.is_none(), "expected a settled failure"),
        }
        assert!(!progress.is_pending());
    }

    #[test]
    fn a_duplicate_family_answer_does_not_settle_the_lookup() {
        let mut progress = DnsProgress::new();
        let ipv4 = DnsResolution::failure("example.test", 443, AddressFamily::Ipv4, "v4 timeout");
        assert!(progress.record(&ipv4).settlement.is_none());
        // Two origins can share a host and port, so the same answer may arrive
        // twice; the second copy must not stand in for the missing family.
        let duplicate =
            DnsResolution::failure("example.test", 443, AddressFamily::Ipv4, "v4 timeout");
        let step = progress.record(&duplicate);
        assert!(!step.usable);
        assert!(step.settlement.is_none());
        assert!(progress.is_pending());
    }

    #[test]
    fn a_later_family_failure_does_not_undo_a_success() {
        let mut progress = DnsProgress::new();
        let ipv4 = DnsResolution::success(
            "example.test",
            443,
            AddressFamily::Ipv4,
            one_address(),
            Duration::from_secs(30),
        );
        let first = progress.record(&ipv4);
        assert!(first.usable);
        assert!(first.settlement.is_none());
        let ipv6 = DnsResolution::failure("example.test", 443, AddressFamily::Ipv6, "v6 nodata");
        let second = progress.record(&ipv6);
        assert!(!second.usable);
        assert_eq!(second.settlement, Some(DnsSettlement::Usable));
    }

    #[test]
    fn a_family_success_settles_the_origin_as_usable() {
        let mut progress = DnsProgress::new();
        let ipv4 = DnsResolution::failure("example.test", 443, AddressFamily::Ipv4, "v4 timeout");
        assert!(progress.record(&ipv4).settlement.is_none());
        let ipv6 = DnsResolution::success(
            "example.test",
            443,
            AddressFamily::Ipv6,
            one_address(),
            Duration::from_secs(30),
        );
        let step = progress.record(&ipv6);
        assert!(step.usable);
        assert_eq!(step.settlement, Some(DnsSettlement::Usable));
        assert!(!progress.is_pending());
    }

    #[test]
    fn http2_config_carries_the_client_limits() {
        let config = ClientConfig {
            max_body_size: 4096,
            max_header_list_size: 8192,
            ..ClientConfig::default()
        };
        let settings = http2_config(&config);
        assert_eq!(settings.max_body_size, 4096);
        assert_eq!(settings.local_settings.max_header_list_size, 8192);
        assert!(!settings.local_settings.enable_push);
    }

    #[test]
    fn http2_config_saturates_an_oversized_header_limit() {
        let config = ClientConfig {
            max_header_list_size: usize::MAX,
            ..ClientConfig::default()
        };
        assert_eq!(
            http2_config(&config).local_settings.max_header_list_size,
            u32::MAX
        );
    }
}
