//! Origin state transitions, waiter queues, and connection accounting.

use super::*;

impl OriginPool {
    /// Creates an empty pool with the given limits.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            origins: HashMap::new(),
        }
    }

    /// Returns the limits this pool applies.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Returns the recorded state, or `None` when the origin is not tracked.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn state(&self, key: &OriginKey) -> Option<OriginState> {
        self.origins.get(key).map(|entry| entry.state)
    }

    /// Returns the mutable entry for `key`, inserting an idle one when absent.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn entry(&mut self, key: &OriginKey) -> &mut OriginEntry {
        self.origins.entry(key.clone()).or_default()
    }

    /// Returns the entry for `key` without inserting one.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn entry_ref(&self, key: &OriginKey) -> Option<&OriginEntry> {
        self.origins.get(key)
    }

    /// Drops every record for `key`; registered connections stay with the client.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn remove_origin(&mut self, key: &OriginKey) {
        drop(self.origins.remove(key));
    }

    /// Appends `id` to the origin's waiter queue.
    ///
    /// Returns `false` when the id is already queued; a duplicate submission
    /// never receives a second terminal callback.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn push_waiter(&mut self, key: &OriginKey, id: RequestId) -> bool {
        let entry = self.entry(key);
        if entry.waiters.contains(&id) {
            return false;
        }
        entry.waiters.push_back(id);
        true
    }

    /// Removes and returns every waiter for `key`, in submission order.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn take_waiters(&mut self, key: &OriginKey) -> Vec<RequestId> {
        let Some(entry) = self.origins.get_mut(key) else {
            return Vec::new();
        };
        entry.waiters.drain(..).collect()
    }

    /// Removes one waiter from `key`.
    ///
    /// Reports [`WaiterRemoval::RemovedLast`] only when the origin is
    /// [`OriginState::ResolvingDns`] and the queue became empty, which is the
    /// signal for the client to take the recorded handles with
    /// [`OriginPool::take_query_handles`] and cancel the shared lookup. This
    /// function never touches the handles itself, so removing one waiter while
    /// others remain keeps the lookup alive.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn remove_waiter(&mut self, key: &OriginKey, id: RequestId) -> WaiterRemoval {
        let Some(entry) = self.origins.get_mut(key) else {
            return WaiterRemoval::NotWaiting;
        };
        let Some(position) = entry.waiters.iter().position(|queued| *queued == id) else {
            return WaiterRemoval::NotWaiting;
        };
        entry.waiters.remove(position);
        if entry.state == OriginState::ResolvingDns && entry.waiters.is_empty() {
            WaiterRemoval::RemovedLast
        } else {
            WaiterRemoval::Removed
        }
    }

    /// Records the lifecycle state for `key`, inserting an entry if needed.
    ///
    /// Returns `false` and leaves the entry unchanged when
    /// [`OriginState::can_transition_to`] rejects the move, so a closed or
    /// draining origin cannot be resurrected directly and a resolving origin
    /// cannot skip [`OriginState::Connecting`].
    ///
    /// Leaving [`OriginState::ResolvingDns`] drops the recorded query handles:
    /// the lookup has finished by then, and cancelling a stale handle is a
    /// no-op in `cares`.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_state(&mut self, key: &OriginKey, state: OriginState) -> bool {
        let entry = self.entry(key);
        if !entry.state.can_transition_to(state) {
            return false;
        }
        if entry.state == OriginState::ResolvingDns && state != OriginState::ResolvingDns {
            entry.query_handles.clear();
        }
        entry.state = state;
        true
    }

    /// Prepares a fresh lookup for `key`.
    ///
    /// Query handles and candidate addresses from an earlier attempt are
    /// cleared so the new lookup never inherits stale state. The origin moves
    /// to [`OriginState::ResolvingDns`] in [`OriginPool::set_query_handles`],
    /// not here: if submitting the queries fails, the origin stays
    /// [`OriginState::Idle`] and the next request retries it instead of
    /// latching it in a resolving state that no completion can leave.
    ///
    /// Returns `true` for [`OriginState::Idle`] and [`OriginState::Closed`];
    /// every other state stays unchanged and returns `false`.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn begin_dns(&mut self, key: &OriginKey) -> bool {
        let entry = self.entry(key);
        if !matches!(entry.state, OriginState::Idle | OriginState::Closed) {
            return false;
        }
        entry.query_handles.clear();
        entry.candidate_ips.clear();
        true
    }

    /// Records the handles of the lookup started for `key` and moves the origin
    /// to [`OriginState::ResolvingDns`].
    ///
    /// Returns `false` without recording anything unless the origin is
    /// [`OriginState::Idle`] or [`OriginState::Closed`], which is the state
    /// [`OriginPool::begin_dns`] leaves behind.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_query_handles(&mut self, key: &OriginKey, handles: Vec<QueryHandle>) -> bool {
        let entry = self.entry(key);
        if !matches!(entry.state, OriginState::Idle | OriginState::Closed) {
            return false;
        }
        entry.query_handles = handles;
        entry.state = OriginState::ResolvingDns;
        true
    }

    /// Removes and returns the recorded queries for `key`.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn take_query_handles(&mut self, key: &OriginKey) -> Vec<QueryHandle> {
        match self.origins.get_mut(key) {
            Some(entry) => std::mem::take(&mut entry.query_handles),
            None => Vec::new(),
        }
    }

    /// Registers a client connection token while the origin has capacity.
    ///
    /// A fresh connection is neither busy nor idle; the client marks it busy
    /// with [`OriginPool::mark_busy`] when a request is dispatched and idle with
    /// [`OriginPool::mark_idle`] once it can carry another request. Returns
    /// `false` when the origin already holds
    /// [`PoolConfig::max_connections_per_origin`] connections or the token is
    /// already registered.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn add_connection(&mut self, key: &OriginKey, connection: u64, now: Instant) -> bool {
        let max_connections = self.config.max_connections_per_origin;
        let entry = self.entry(key);
        if entry.connections.len() >= max_connections
            || entry
                .connections
                .iter()
                .any(|pooled| pooled.connection == connection)
        {
            return false;
        }
        entry.connections.push(PooledConnection {
            connection,
            created: now,
            idle_since: None,
            streams: 0,
            busy: false,
        });
        true
    }

    /// Forgets a connection token.
    ///
    /// Returns `true` when the token was registered for `key`; an unknown
    /// origin or an unknown token returns `false` without inserting an entry.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn remove_connection(&mut self, key: &OriginKey, connection: u64) -> bool {
        let Some(entry) = self.origins.get_mut(key) else {
            return false;
        };
        let before = entry.connections.len();
        entry
            .connections
            .retain(|pooled| pooled.connection != connection);
        entry.connections.len() != before
    }

    /// Marks a connection as carrying no request as of `now`.
    ///
    /// Unknown keys and tokens are ignored.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn mark_idle(&mut self, key: &OriginKey, connection: u64, now: Instant) {
        if let Some(pooled) = self.connection_mut(key, connection) {
            pooled.idle_since = Some(now);
            pooled.busy = false;
        }
    }

    /// Marks a connection as processing at least one request.
    ///
    /// A busy connection is exempt from eviction until it is marked idle
    /// again, so an in-flight HTTP/1.1 exchange or a live HTTP/2 stream keeps
    /// its socket. Unknown keys and tokens are ignored.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn mark_busy(&mut self, key: &OriginKey, connection: u64) {
        if let Some(pooled) = self.connection_mut(key, connection) {
            pooled.idle_since = None;
            pooled.busy = true;
        }
    }

    /// Counts connections the client marked idle, or zero for an unknown
    /// origin.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn idle_count(&self, key: &OriginKey) -> usize {
        self.origins.get(key).map_or(0, |entry| {
            entry
                .connections
                .iter()
                .filter(|pooled| pooled.idle_since.is_some())
                .count()
        })
    }

    /// Counts registered connections, or zero for an unknown origin.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn connection_count(&self, key: &OriginKey) -> usize {
        self.origins
            .get(key)
            .map_or(0, |entry| entry.connections.len())
    }

    /// Evicts over-age and surplus idle connections and returns
    /// `(origin, token)` pairs for the client to close.
    ///
    /// A connection is a candidate only while the client reports it as not
    /// busy and without streams, so an exchange or an HTTP/2 stream that is
    /// still running never loses its socket. A candidate is evicted when it is
    /// older than [`PoolConfig::max_lifetime`], when it has been idle for at
    /// least [`PoolConfig::idle_timeout`], or when it is one of the oldest idle
    /// connections beyond [`PoolConfig::max_idle_per_origin`]. A connection
    /// that was never marked idle has no idle timestamp, so only the lifetime
    /// limit applies to it.
    ///
    /// Each connection is reported at most once. Evicted connections leave the
    /// pool before this returns, while the origin state and its waiters stay
    /// untouched.
    ///
    /// A timestamp later than `now` counts as zero elapsed time.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn expired(&mut self, now: Instant) -> Vec<(OriginKey, u64)> {
        let config = &self.config;
        let mut expired: Vec<(OriginKey, u64)> = Vec::new();
        for (key, entry) in &mut self.origins {
            if entry.connections.is_empty() {
                continue;
            }

            let mut removed: Vec<u64> = Vec::new();
            entry.connections.retain(|pooled| {
                if pooled.busy || pooled.streams != 0 {
                    return true;
                }
                let too_old = now.saturating_duration_since(pooled.created) >= config.max_lifetime;
                let idle_too_long = pooled.idle_since.is_some_and(|since| {
                    now.saturating_duration_since(since) >= config.idle_timeout
                });
                if too_old || idle_too_long {
                    removed.push(pooled.connection);
                    false
                } else {
                    true
                }
            });
            expired.extend(removed.into_iter().map(|token| (key.clone(), token)));

            let mut idle: Vec<usize> = entry
                .connections
                .iter()
                .enumerate()
                .filter(|(_, pooled)| pooled.idle_since.is_some() && pooled.streams == 0)
                .map(|(index, _)| index)
                .collect();
            let excess = idle.len().saturating_sub(config.max_idle_per_origin);
            if excess == 0 {
                continue;
            }
            idle.sort_by_key(|&index| entry.connections[index].idle_since);
            let tokens: Vec<u64> = idle[..excess]
                .iter()
                .map(|&index| entry.connections[index].connection)
                .collect();
            // Removing from the highest index first keeps the lower ones valid.
            idle[..excess].sort_unstable();
            for &index in idle[..excess].iter().rev() {
                entry.connections.remove(index);
            }
            expired.extend(tokens.into_iter().map(|token| (key.clone(), token)));
        }
        expired
    }

    /// Iterates over every tracked origin and its entry.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn origins(&self) -> impl Iterator<Item = (&OriginKey, &OriginEntry)> {
        self.origins.iter()
    }

    /// Returns the tracked connection for `key` without inserting an entry.
    fn connection_mut(&mut self, key: &OriginKey, token: u64) -> Option<&mut PooledConnection> {
        self.origins
            .get_mut(key)?
            .connections
            .iter_mut()
            .find(|pooled| pooled.connection == token)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use nexora_proto::Scheme;

    use super::{OriginKey, OriginPool, OriginState, PoolConfig, WaiterRemoval};
    use crate::inbox::RequestId;

    fn connection_snapshot(
        pool: &OriginPool,
        key: &OriginKey,
        token: u64,
    ) -> Option<(Option<Instant>, usize)> {
        let entry = pool.entry_ref(key)?;
        let pooled = entry
            .connections
            .iter()
            .find(|pooled| pooled.connection == token)?;
        Some((pooled.idle_since, pooled.streams))
    }

    fn set_streams(pool: &mut OriginPool, key: &OriginKey, token: u64, streams: usize) {
        let entry = pool.entry(key);
        if let Some(conn) = entry
            .connections
            .iter_mut()
            .find(|conn| conn.connection == token)
        {
            conn.streams = streams;
        }
    }

    #[test]
    fn state_machine_accepts_the_lifecycle_paths() {
        let mut pool = OriginPool::default();
        let key = OriginKey::new(Scheme::Https, "lifecycle.test", 443);
        for state in [
            OriginState::ResolvingDns,
            OriginState::Connecting,
            OriginState::Handshaking,
            OriginState::ReadyHttp2,
            // A second connection negotiated HTTP/1.1 on the same origin.
            OriginState::ReadyHttp1,
            // A parallel connection was opened for the queued waiters.
            OriginState::Connecting,
            OriginState::Draining,
            OriginState::Idle,
            OriginState::Closed,
            OriginState::Connecting,
        ] {
            assert!(pool.set_state(&key, state), "rejected {state:?}");
        }
        assert_eq!(pool.state(&key), Some(OriginState::Connecting));
    }

    #[test]
    fn state_machine_rejects_skipped_and_resurrected_transitions() {
        let mut pool = OriginPool::default();
        let key = OriginKey::new(Scheme::Http, "transitions.test", 80);

        assert!(pool.set_state(&key, OriginState::ResolvingDns));
        assert!(!pool.set_state(&key, OriginState::ReadyHttp1));
        assert_eq!(pool.state(&key), Some(OriginState::ResolvingDns));

        assert!(pool.set_state(&key, OriginState::Closed));
        assert!(!pool.set_state(&key, OriginState::ReadyHttp2));
        assert_eq!(pool.state(&key), Some(OriginState::Closed));

        assert!(pool.set_state(&key, OriginState::Draining));
        assert!(!pool.set_state(&key, OriginState::Connecting));
        assert_eq!(pool.state(&key), Some(OriginState::Draining));

        assert!(pool.set_state(&key, OriginState::Idle));
        assert!(
            pool.set_state(&key, OriginState::ReadyHttp1),
            "an idle origin may accept a connection that finished before it was reset"
        );
    }

    #[test]
    fn begin_dns_stays_retryable_until_handles_are_recorded() {
        let mut pool = OriginPool::default();
        let key = OriginKey::new(Scheme::Https, "lookup.test", 443);

        assert!(pool.begin_dns(&key));
        assert_eq!(pool.state(&key), Some(OriginState::Idle));
        // Submitting the queries failed: the next request must be able to retry.
        assert!(pool.begin_dns(&key));

        assert!(pool.set_query_handles(&key, Vec::new()));
        assert_eq!(pool.state(&key), Some(OriginState::ResolvingDns));
        assert!(!pool.begin_dns(&key));
        assert!(!pool.set_query_handles(&key, Vec::new()));
        assert_eq!(pool.take_query_handles(&key), Vec::new());
    }

    #[test]
    fn remove_waiter_reports_removed_last_only_while_resolving() {
        use WaiterRemoval::{NotWaiting, Removed, RemovedLast};

        let mut pool = OriginPool::default();
        let key = OriginKey::new(Scheme::Http, "waiters.test", 80);
        assert!(pool.begin_dns(&key));
        assert!(pool.set_query_handles(&key, Vec::new()));
        assert!(pool.push_waiter(&key, RequestId::new(1)));
        assert!(pool.push_waiter(&key, RequestId::new(2)));

        assert_eq!(pool.remove_waiter(&key, RequestId::new(9)), NotWaiting);
        // Removing one of two waiters keeps the shared lookup alive.
        assert_eq!(pool.remove_waiter(&key, RequestId::new(1)), Removed);
        assert_eq!(pool.state(&key), Some(OriginState::ResolvingDns));
        // Only the last waiter signals that the recorded handles may be cancelled.
        assert_eq!(pool.remove_waiter(&key, RequestId::new(2)), RemovedLast);
        assert_eq!(pool.state(&key), Some(OriginState::ResolvingDns));

        // Past resolution the queue no longer owns a cancelable lookup.
        assert!(pool.set_state(&key, OriginState::Connecting));
        assert!(pool.set_state(&key, OriginState::ReadyHttp1));
        assert!(pool.push_waiter(&key, RequestId::new(3)));
        assert_eq!(pool.remove_waiter(&key, RequestId::new(3)), Removed);
    }

    #[test]
    fn push_waiter_deduplicates_request_ids() {
        let mut pool = OriginPool::default();
        let key = OriginKey::new(Scheme::Https, "dedup.test", 443);
        let first = RequestId::new(7);

        assert!(pool.push_waiter(&key, first));
        assert!(!pool.push_waiter(&key, first));
        assert!(pool.push_waiter(&key, RequestId::new(8)));

        assert_eq!(pool.take_waiters(&key), vec![first, RequestId::new(8)]);
        assert_eq!(pool.take_waiters(&key), Vec::<RequestId>::new());
    }

    #[test]
    fn add_connection_respects_capacity_and_rejects_duplicates() {
        let config = PoolConfig {
            max_connections_per_origin: 2,
            ..PoolConfig::default()
        };
        let mut pool = OriginPool::new(config);
        let key = OriginKey::new(Scheme::Https, "capacity.test", 443);
        let now = Instant::now();

        assert!(pool.add_connection(&key, 10, now));
        assert!(!pool.add_connection(&key, 10, now));
        assert!(pool.add_connection(&key, 11, now));
        assert!(!pool.add_connection(&key, 12, now));
        assert_eq!(pool.connection_count(&key), 2);

        assert!(pool.remove_connection(&key, 11));
        assert!(!pool.remove_connection(&key, 11));
        assert!(pool.add_connection(&key, 12, now));
        assert_eq!(pool.connection_count(&key), 2);
    }

    #[test]
    fn expired_evicts_on_idle_timeout_and_max_lifetime() {
        let mut pool = OriginPool::default();
        let key = OriginKey::new(Scheme::Https, "age.test", 443);
        let start = Instant::now();
        assert!(pool.add_connection(&key, 1, start));
        assert!(pool.add_connection(&key, 2, start));
        pool.mark_idle(&key, 1, start);
        pool.mark_idle(&key, 2, start + Duration::from_secs(50));

        assert_eq!(
            pool.expired(start + Duration::from_secs(100)),
            vec![(key.clone(), 1)]
        );
        assert_eq!(pool.connection_count(&key), 1);

        assert_eq!(
            pool.expired(start + Duration::from_secs(301)),
            vec![(key.clone(), 2)]
        );
        assert_eq!(pool.connection_count(&key), 0);
        assert_eq!(pool.idle_count(&key), 0);
        assert_eq!(pool.state(&key), Some(OriginState::Idle));
    }

    #[test]
    fn expired_never_evicts_a_connection_in_use() {
        let config = PoolConfig {
            max_connections_per_origin: 3,
            max_idle_per_origin: 3,
            idle_timeout: Duration::from_secs(10),
            max_lifetime: Duration::from_secs(20),
        };
        let mut pool = OriginPool::new(config);
        let key = OriginKey::new(Scheme::Https, "busy.test", 443);
        let start = Instant::now();
        assert!(pool.add_connection(&key, 1, start));
        assert!(pool.add_connection(&key, 2, start));
        assert!(pool.add_connection(&key, 3, start));
        pool.mark_busy(&key, 1);
        pool.mark_idle(&key, 2, start);
        // The stream counter protects a connection even when it is not marked busy.
        set_streams(&mut pool, &key, 3, 1);

        let late = start + Duration::from_secs(1_000);
        assert_eq!(pool.expired(late), vec![(key.clone(), 2)]);
        assert_eq!(pool.connection_count(&key), 2);
        assert_eq!(connection_snapshot(&pool, &key, 1), Some((None, 0)));

        // Once the stream ends and the client marks both sockets idle, the
        // lifetime limit reaps them.
        set_streams(&mut pool, &key, 3, 0);
        pool.mark_idle(&key, 3, late);
        pool.mark_idle(&key, 1, late);
        assert_eq!(pool.expired(late), vec![(key.clone(), 1), (key.clone(), 3)]);
        assert_eq!(pool.connection_count(&key), 0);
    }

    #[test]
    fn expired_evicts_surplus_idle_connections_oldest_first() {
        let config = PoolConfig {
            max_idle_per_origin: 1,
            idle_timeout: Duration::from_secs(3_600),
            max_lifetime: Duration::from_secs(3_600),
            ..PoolConfig::default()
        };
        let mut pool = OriginPool::new(config);
        let key = OriginKey::new(Scheme::Http, "surplus.test", 80);
        let start = Instant::now();
        assert!(pool.add_connection(&key, 1, start));
        assert!(pool.add_connection(&key, 2, start));
        assert!(pool.add_connection(&key, 3, start));
        pool.mark_idle(&key, 1, start);
        pool.mark_idle(&key, 2, start + Duration::from_secs(1));
        pool.mark_idle(&key, 3, start + Duration::from_secs(2));

        assert_eq!(
            pool.expired(start + Duration::from_secs(3)),
            vec![(key.clone(), 1), (key.clone(), 2)]
        );
        assert_eq!(pool.connection_count(&key), 1);
        assert_eq!(pool.idle_count(&key), 1);
    }

    #[test]
    fn origin_keys_normalize_host_spelling() {
        let dotted = OriginKey::new(Scheme::Http, "Example.COM.", 80);
        let plain = OriginKey::new(Scheme::Http, "example.com", 80);
        let bracketed = OriginKey::new(Scheme::Https, "[2001:DB8::1]", 443);
        let bare = OriginKey::new(Scheme::Https, "2001:db8::1", 443);

        assert_eq!(dotted, plain);
        assert_eq!(bracketed, bare);
        assert_eq!(plain.authority(), "example.com:80");
        assert_eq!(bare.authority(), "[2001:db8::1]:443");
        assert_ne!(
            OriginKey::new(Scheme::Http, "example.com", 80),
            OriginKey::new(Scheme::Http, "example.com", 8080)
        );
    }
}
