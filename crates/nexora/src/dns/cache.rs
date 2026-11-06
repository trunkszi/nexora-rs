//! TTL cache storage, address-set expiry, and bounded eviction.

use std::num::NonZeroU64;

use uarch::{
    mem::{L1, prefetch_read},
    prelude::*,
};

use super::*;

#[derive(Debug)]
struct CachedAnswer {
    entry: DnsCacheEntry,
    cursor: u64,
    divisor: FastDivisorU64,
}

/// One cached address set and the instant its resolver TTL elapses.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// Addresses returned for the cached host and port.
    pub addrs: Vec<SocketAddr>,
    /// Absolute instant after which the entry must not be served.
    pub expires_at: Instant,
}

impl DnsCacheEntry {
    /// Reports whether the entry is expired at `now`.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[hot_inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Bounded cache of resolved address sets keyed by host name and port.
///
/// Keys are stored in their normalized form, so lookup is case-insensitive and
/// ignores a single trailing dot. Zero-TTL answers and empty address lists are
/// never stored.
#[derive(Debug)]
pub struct DnsCache {
    entries: HashMap<(String, u16), CachedAnswer>,
    capacity: usize,
}

impl DnsCache {
    /// Creates an empty cache holding at most `capacity` entries.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Stores an answer, evicting the earliest-expiring entry when full.
    ///
    /// A zero `ttl` or an empty `addrs` list is ignored rather than stored,
    /// because such an answer cannot be served without contradicting its own
    /// lifetime or address set.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn insert(
        &mut self,
        host: &str,
        port: u16,
        addrs: Vec<SocketAddr>,
        ttl: Duration,
        now: Instant,
    ) {
        if ttl.is_zero() || addrs.is_empty() || self.capacity == 0 {
            return;
        }
        let key = (normalize_host(host), port);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.evict_earliest();
        }
        // An expiry beyond the representable `Instant` range is treated as
        // already expired: refusing to serve it is safer than panicking.
        let expires_at = match now.checked_add(ttl) {
            Some(expiry) => expiry,
            None => now,
        };
        let divisor =
            FastDivisorU64::new(NonZeroU64::new(addrs.len() as u64).unwrap_or(NonZeroU64::MIN));
        drop(self.entries.insert(
            key,
            CachedAnswer {
                entry: DnsCacheEntry { addrs, expires_at },
                cursor: 0,
                divisor,
            },
        ));
    }

    /// Returns a live answer, rotating the preferred address on each cache hit.
    /// Expired entries are dropped on access.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn lookup(&mut self, host: &str, port: u16, now: Instant) -> Option<Vec<SocketAddr>> {
        let key = (normalize_host(host), port);
        match self.entries.get_mut(&key) {
            Some(answer) if !answer.entry.is_expired(now) => {
                prefetch_read::<L1, _>(answer.entry.addrs.as_ptr());
                let mut addrs = answer.entry.addrs.clone();
                addrs.rotate_left(answer.cursor as usize);
                answer.cursor = answer.divisor.rem(answer.cursor + 1);
                Some(addrs)
            }
            Some(_) => {
                drop(self.entries.remove(&key));
                None
            }
            None => None,
        }
    }

    /// Removes the entry for `host` and `port`, if present.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn remove(&mut self, host: &str, port: u16) {
        drop(self.entries.remove(&(normalize_host(host), port)));
    }

    /// Removes every entry.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of stored entries, including expired ones.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether no entry is stored.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the maximum number of stored entries.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Evicts the entry with the earliest expiry instant.
    ///
    /// A linear scan is used because the cache is small and eviction runs only
    /// when a new key arrives at capacity.
    fn evict_earliest(&mut self) {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.entry.expires_at)
            .map(|(key, _)| key.clone());
        if let Some(victim) = victim {
            drop(self.entries.remove(&victim));
        }
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    #[test]
    fn cache_cycles_and_replacement_resets() {
        let now = Instant::now();
        let addrs: Vec<_> = [1, 2, 3]
            .map(|last| SocketAddr::from(([127, 0, 0, last], 80)))
            .into();
        let mut cache = DnsCache::new(1);
        cache.insert("host", 80, addrs.clone(), Duration::from_secs(5), now);
        for index in 0..10 {
            assert_eq!(
                cache.lookup("host", 80, now).map(|a| a[0]),
                Some(addrs[index % 3])
            );
        }
        cache.insert("host", 80, addrs.clone(), Duration::from_secs(5), now);
        assert_eq!(cache.lookup("host", 80, now), Some(addrs));
        assert!(
            cache
                .lookup("host", 80, now + Duration::from_secs(5))
                .is_none()
        );
    }
}
