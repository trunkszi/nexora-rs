//! Static host overrides, a TTL-bounded address cache, and c-ares queries
//! driven by the shared proactor.
//!
//! [`HostResolver`] submits one `A` and one `AAAA` query per lookup, stages the
//! c-ares socket and deadline work through [`HostResolver::flush`], and routes
//! each completion into a [`DnsResolution`] staged on the [`SubsystemInbox`].
//! Overrides added through [`HostResolver::resolve_host`] and answers held in
//! [`DnsCache`] are consulted before a query is sent.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use cares::{DnsRecordType, DnsSection};
use liburing::{Completion, CompletionDispatcher, Proactor, SubmissionContext, SubsystemId};

use crate::{
    error::{Error, Result},
    inbox::{AddressFamily, DnsResolution, SubsystemInbox},
};

/// Entry capacity of the address cache owned by every [`HostResolver`].
const DEFAULT_CACHE_CAPACITY: usize = 256;

/// Socket-bridge capacity used by [`HostResolver::default_resolver`].
const DEFAULT_BRIDGE_CAPACITY: usize = 64;

/// Canonical cache and override key for a host name.
///
/// Lowercasing copies the name once so a caller's buffer is never retained.
/// Exactly one trailing dot is removed because it marks the absolute name form;
/// stripping further dots would let a malformed name alias a valid one.
fn normalize_host(host: &str) -> String {
    let lowered = host.to_ascii_lowercase();
    match lowered.strip_suffix('.') {
        Some(stripped) => stripped.to_string(),
        None => lowered,
    }
}

mod cache;
pub use cache::{DnsCache, DnsCacheEntry};

/// Static overrides, an address cache, and a proactor-driven c-ares channel.
///
/// The resolver is registered on the same ring as the client. Query completions
/// only stage a [`DnsResolution`] on the inbox; the client drive loop applies
/// the result, so a completion never mutates connection state directly.
///
/// The owner must call [`liburing::Proactor::shutdown`] before dropping this
/// value: the driver retains armed timeout operands that must outlive their
/// final completions.
pub struct HostResolver {
    subsystem: SubsystemId,
    driver: cares::ProactorResolver,
    static_hosts: HashMap<(String, u16), Vec<SocketAddr>>,
    cache: DnsCache,
    _guard: cares::LibraryGuard,
}

impl HostResolver {
    /// Creates a resolver bound to one proactor subsystem.
    ///
    /// `capacity` is the socket-bridge capacity of the c-ares driver; the
    /// address cache always holds 256 entries.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] when `dns_subsystem` is the reserved
    /// internal slot or when `servers_csv` is empty, because c-ares treats an
    /// empty server list as a request to blank every configured server.
    /// Returns the library-initialization, option, or socket-bridge error from
    /// the underlying driver.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(
        dns_subsystem: SubsystemId,
        options: cares::ResolverOptions,
        servers_csv: &str,
        capacity: usize,
    ) -> Result<Self> {
        if dns_subsystem == SubsystemId::INTERNAL {
            return Err(Error::InvalidState(
                "DNS subsystem id 0 is reserved for the proactor".to_string(),
            ));
        }
        if servers_csv.is_empty() {
            return Err(Error::InvalidState(
                "DNS server list must not be empty".to_string(),
            ));
        }
        let guard = cares::LibraryGuard::acquire()?;
        let driver = cares::ProactorResolver::new(dns_subsystem, options, servers_csv, capacity)?;
        Ok(Self {
            subsystem: dns_subsystem,
            driver,
            static_hosts: HashMap::new(),
            cache: DnsCache::new(DEFAULT_CACHE_CAPACITY),
            _guard: guard,
        })
    }

    /// Creates a resolver from the system resolver configuration.
    ///
    /// A temporary channel reads the platform server list because
    /// [`cares::ResolverOptions`] is not cloneable and [`cares::Resolver::new`]
    /// consumes it. The probe is dropped before the real driver is built.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] when the system configuration lists no
    /// servers. Hermetic runners without a resolver configuration must pass
    /// explicit servers to [`Self::new`]. Otherwise the same errors as
    /// [`Self::new`] apply.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn default_resolver(dns_subsystem: SubsystemId) -> Result<Self> {
        let probe_options = cares::ResolverOptions::builder().build()?;
        let probe = cares::Resolver::new(probe_options)?;
        let servers = probe.servers_csv()?;
        drop(probe);
        if servers.is_empty() {
            return Err(Error::InvalidState(
                "system resolver configuration lists no DNS servers".to_string(),
            ));
        }
        let options = cares::ResolverOptions::builder().build()?;
        Self::new(dns_subsystem, options, &servers, DEFAULT_BRIDGE_CAPACITY)
    }

    /// Returns the subsystem this resolver is registered under.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn subsystem_id(&self) -> SubsystemId {
        self.subsystem
    }

    /// Adds a static override for `host` and `port`.
    ///
    /// An empty `addrs` list removes the override instead of storing a lookup
    /// that can never succeed.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn resolve_host(&mut self, host: impl Into<String>, port: u16, addrs: Vec<IpAddr>) {
        let host: String = host.into();
        let key = (normalize_host(&host), port);
        if addrs.is_empty() {
            drop(self.static_hosts.remove(&key));
            return;
        }
        let mapped = addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        drop(self.static_hosts.insert(key, mapped));
    }

    /// Removes the static override and cached answer for `host` and `port`.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn clear_static(&mut self, host: &str, port: u16) {
        drop(self.static_hosts.remove(&(normalize_host(host), port)));
        self.cache.remove(host, port);
    }

    /// Returns an address set from the overrides, an IP literal, or the cache.
    ///
    /// Lookup order is static override, IP literal, cache. An IP literal needs
    /// no DNS query, so `host` itself is returned with `port` applied.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn lookup_static_or_cache(
        &mut self,
        host: &str,
        port: u16,
        now: Instant,
    ) -> Option<Vec<SocketAddr>> {
        let key = (normalize_host(host), port);
        if let Some(addrs) = self.static_hosts.get(&key) {
            return Some(addrs.clone());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(vec![SocketAddr::new(ip, port)]);
        }
        self.cache.lookup(host, port, now)
    }

    /// Starts the `A` and `AAAA` queries for `host` and `port`.
    ///
    /// Both queries are submitted before the driver is flushed, so the returned
    /// handles cover every query the proactor may complete. A failure while
    /// submitting the second query or flushing cancels the queries already
    /// accepted, because no caller can observe handles that were never
    /// returned. A callback may run synchronously inside submission; if the
    /// second submission then fails, a resolution for this host and port may
    /// already be staged on the inbox.
    ///
    /// # Errors
    /// Returns a resolver submission error, or the driver flush error. Queries
    /// already submitted are cancelled before the error is returned.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn start_query(
        &mut self,
        proactor: &mut Proactor,
        host: &str,
        port: u16,
        inbox: &SubsystemInbox,
    ) -> Result<Vec<cares::QueryHandle>> {
        let mut handles = Vec::with_capacity(2);
        let ipv4 = self.submit_family_query(
            host,
            port,
            DnsRecordType::A,
            AddressFamily::Ipv4,
            inbox.clone(),
        )?;
        handles.push(ipv4);
        match self.submit_family_query(
            host,
            port,
            DnsRecordType::AAAA,
            AddressFamily::Ipv6,
            inbox.clone(),
        ) {
            Ok(ipv6) => handles.push(ipv6),
            Err(error) => {
                self.cancel_queries(&handles);
                return Err(error);
            }
        }
        if let Err(error) = self.driver.flush(proactor) {
            self.cancel_queries(&handles);
            return Err(Error::from(error));
        }
        Ok(handles)
    }

    /// Cancels every query in `handles`, ignoring stale handles.
    ///
    /// A handle whose query already completed is stale, and cancellation is
    /// then a no-op rather than an error the caller could act on. Cancellation
    /// retires the callback slot; c-ares exposes no per-query abort, so the
    /// channel may keep the query in flight until it completes or times out.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn cancel_queries(&mut self, handles: &[cares::QueryHandle]) {
        for handle in handles {
            // A stale handle means the query already completed, so the
            // cancellation is already satisfied.
            drop(self.driver.resolver.cancel_query(*handle));
        }
    }

    /// Stores an answer in the address cache.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn store_cache(
        &mut self,
        host: &str,
        port: u16,
        addrs: Vec<SocketAddr>,
        ttl: Duration,
        now: Instant,
    ) {
        self.cache.insert(host, port, addrs, ttl, now);
    }

    /// Borrows the address cache.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    /// Mutably borrows the address cache.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn cache_mut(&mut self) -> &mut DnsCache {
        &mut self.cache
    }

    /// Stages queued c-ares socket work and the next deadline on the ring.
    ///
    /// # Errors
    /// Returns a proactor submission, timer, or channel error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn flush(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.driver.flush(proactor)?;
        Ok(())
    }

    /// Stops queries and stages cancellation while leaving the shared ring open.
    /// # Errors
    /// Returns resolver or cancellation-submission errors; pending I/O stays owned.
    /// # Panics
    /// This function does not panic.
    pub fn begin_shutdown(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.driver.begin_shutdown(proactor)?;
        Ok(())
    }

    /// Reports whether DNS targets or cancellation acknowledgments remain live.
    /// # Errors
    /// This function does not return errors.
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn has_pending_io(&self) -> bool {
        self.driver.has_pending_io()
    }

    /// Consumes one completion addressed to this resolver subsystem.
    ///
    /// Completions for other subsystems are ignored so a caller may forward
    /// every completion without filtering.
    ///
    /// # Errors
    /// Returns a driver completion-dispatch error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        self.dispatch_completion(completion, submissions)
    }

    /// Submits one query whose completion stages a [`DnsResolution`].
    ///
    /// # Errors
    /// Returns a resolver submission error.
    fn submit_family_query(
        &mut self,
        host: &str,
        port: u16,
        record_type: DnsRecordType,
        family: AddressFamily,
        inbox: SubsystemInbox,
    ) -> Result<cares::QueryHandle> {
        let name = host.to_string();
        let handle =
            self.driver
                .resolver
                .submit_query(host, record_type, move |_ctx, outcome| {
                    inbox.dns_resolved(resolution_from_outcome(&name, port, family, &outcome));
                })?;
        Ok(handle)
    }

    /// Dispatches a completion to the c-ares driver.
    ///
    /// # Errors
    /// Returns a driver completion-dispatch error.
    fn dispatch_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        if completion.operation_id.subsystem_id() != self.subsystem {
            return Ok(());
        }
        self.driver.dispatch(completion, submissions)?;
        Ok(())
    }
}

impl CompletionDispatcher for HostResolver {
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        match self.dispatch_completion(completion, submissions) {
            Ok(()) => Ok(()),
            Err(_) => Err(liburing::UringError::InvalidConfig("DNS resolver failure")),
        }
    }
}

/// Converts one c-ares query outcome into a resolution for the inbox.
///
/// Records with an unmodeled type are skipped. The reported TTL is the minimum
/// across every answer record, including the CNAME chain, so a cached entry
/// never outlives the shortest-lived record it depends on.
fn resolution_from_outcome(
    host: &str,
    port: u16,
    family: AddressFamily,
    outcome: &cares::QueryOutcome<'_>,
) -> DnsResolution {
    let Some(record) = outcome.record else {
        return DnsResolution::failure(host, port, family, outcome.status.message());
    };
    let wanted = match family {
        AddressFamily::Ipv4 => DnsRecordType::A,
        AddressFamily::Ipv6 => DnsRecordType::AAAA,
    };
    let mut addrs = Vec::new();
    let mut minimum_ttl: Option<u32> = None;
    for index in 0..record.rr_count(DnsSection::Answer) {
        let Ok(rr) = record.rr(DnsSection::Answer, index) else {
            continue;
        };
        // DNSSEC answers mix unmodeled types such as RRSIG into the section; an
        // unknown type must not discard the address records beside it.
        let Ok(record_type) = rr.record_type() else {
            continue;
        };
        let ttl = rr.ttl();
        minimum_ttl = Some(minimum_ttl.map_or(ttl, |current| current.min(ttl)));
        if record_type != wanted {
            continue;
        }
        let address = match family {
            AddressFamily::Ipv4 => match rr.as_a() {
                Ok(record) => SocketAddr::new(IpAddr::V4(record.address), port),
                Err(_) => continue,
            },
            AddressFamily::Ipv6 => match rr.as_aaaa() {
                Ok(record) => {
                    if record.address.is_unicast_link_local() {
                        continue;
                    }
                    SocketAddr::new(IpAddr::V6(record.address), port)
                }
                Err(_) => continue,
            },
        };
        if !addrs.contains(&address) {
            addrs.push(address);
        }
    }
    if addrs.is_empty() {
        return DnsResolution::failure(
            host,
            port,
            family,
            "no usable A/AAAA records in the answer",
        );
    }
    let ttl = match minimum_ttl {
        Some(seconds) => Duration::from_secs(u64::from(seconds)),
        None => Duration::ZERO,
    };
    DnsResolution::success(host, port, family, addrs, ttl)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use cares::{
        ARecord, AaaaRecord, AresStatus, CnameRecord, DnsClass, DnsRecord, QueryOutcome,
        types::{DnsFlags, DnsOpcode, DnsRcode},
    };

    use super::*;

    /// Builds a mixed answer: duplicated A records, a second A record with the
    /// shortest address TTL, a usable AAAA record, a link-local AAAA record,
    /// and a CNAME carrying the overall minimum TTL.
    fn mixed_answer() -> Result<DnsRecord> {
        let mut record = DnsRecord::new(
            0,
            DnsFlags::QR | DnsFlags::RD,
            DnsOpcode::Query,
            DnsRcode::NoError,
        )?;
        for (address, ttl) in [
            (Ipv4Addr::new(192, 0, 2, 1), 30),
            (Ipv4Addr::new(192, 0, 2, 1), 30),
            (Ipv4Addr::new(192, 0, 2, 2), 20),
        ] {
            let mut rr = record.rr_add(
                DnsSection::Answer,
                "example.test",
                DnsRecordType::A,
                DnsClass::IN,
                ttl,
            )?;
            rr.set(&ARecord { address })?;
        }
        let mut rr = record.rr_add(
            DnsSection::Answer,
            "example.test",
            DnsRecordType::AAAA,
            DnsClass::IN,
            60,
        )?;
        rr.set(&AaaaRecord {
            address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
        })?;
        let mut rr = record.rr_add(
            DnsSection::Answer,
            "example.test",
            DnsRecordType::AAAA,
            DnsClass::IN,
            10,
        )?;
        rr.set(&AaaaRecord {
            address: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        })?;
        let mut rr = record.rr_add(
            DnsSection::Answer,
            "alias.example.test",
            DnsRecordType::CNAME,
            DnsClass::IN,
            5,
        )?;
        rr.set(&CnameRecord {
            cname: String::from("example.test"),
        })?;
        Ok(record)
    }

    #[test]
    fn resolution_keeps_only_the_requested_family() -> Result<()> {
        let record = mixed_answer()?;
        let outcome = QueryOutcome {
            status: AresStatus::Success,
            timeouts: 0,
            record: Some(record.as_ref()),
        };
        let ipv4 = resolution_from_outcome("example.test", 443, AddressFamily::Ipv4, &outcome);
        assert!(ipv4.is_usable());
        assert_eq!(ipv4.family, AddressFamily::Ipv4);
        assert_eq!(ipv4.host, "example.test");
        assert_eq!(ipv4.port, 443);
        assert_eq!(
            ipv4.addrs,
            vec![
                SocketAddr::from(([192, 0, 2, 1], 443)),
                SocketAddr::from(([192, 0, 2, 2], 443)),
            ]
        );
        // The CNAME's TTL is the minimum across the whole answer.
        assert_eq!(ipv4.ttl, Duration::from_secs(5));
        let ipv6 = resolution_from_outcome("example.test", 443, AddressFamily::Ipv6, &outcome);
        assert!(ipv6.is_usable());
        assert_eq!(ipv6.family, AddressFamily::Ipv6);
        assert_eq!(
            ipv6.addrs,
            vec![SocketAddr::from((
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                443,
            ))]
        );
        assert_eq!(ipv6.ttl, Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn resolution_reports_failures_for_nodata_and_errors() -> Result<()> {
        let empty = DnsRecord::new(0, DnsFlags::QR, DnsOpcode::Query, DnsRcode::NoError)?;
        let nodata = QueryOutcome {
            status: AresStatus::Success,
            timeouts: 0,
            record: Some(empty.as_ref()),
        };
        let resolution = resolution_from_outcome("example.test", 443, AddressFamily::Ipv6, &nodata);
        assert!(!resolution.is_usable());
        assert!(resolution.addrs.is_empty());
        assert!(resolution.error.is_some());
        let not_found = QueryOutcome {
            status: AresStatus::NotFound,
            timeouts: 1,
            record: None,
        };
        let resolution =
            resolution_from_outcome("example.test", 443, AddressFamily::Ipv4, &not_found);
        assert!(!resolution.is_usable());
        assert!(
            resolution
                .error
                .as_deref()
                .is_some_and(|message| !message.is_empty())
        );
        Ok(())
    }
}
