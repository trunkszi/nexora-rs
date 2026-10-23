//! Public DNS cache and static-override precedence contracts.
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use nexora::{DnsCache, HostResolver, Result, SubsystemId};

fn address(port: u16) -> Vec<SocketAddr> {
    vec![SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        port,
    )]
}

#[test]
fn cache_serves_live_entries_and_drops_expired_ones() {
    let now = Instant::now();
    let mut cache = DnsCache::new(4);
    cache.insert(
        "Example.COM.",
        443,
        address(443),
        Duration::from_secs(30),
        now,
    );
    assert_eq!(
        cache.lookup("example.com", 443, now + Duration::from_secs(10)),
        Some(address(443))
    );
    assert!(
        cache
            .lookup("example.com", 443, now + Duration::from_secs(30))
            .is_none()
    );
    assert!(cache.is_empty());
}

#[test]
fn cache_rejects_zero_ttl_and_empty_address_lists() {
    let now = Instant::now();
    let mut cache = DnsCache::new(4);
    cache.insert("a.test", 80, address(80), Duration::ZERO, now);
    cache.insert("b.test", 80, Vec::new(), Duration::from_secs(30), now);
    assert!(cache.is_empty());
}

#[test]
fn cache_evicts_the_earliest_expiring_entry() {
    let now = Instant::now();
    let mut cache = DnsCache::new(1);
    cache.insert("short.test", 80, address(80), Duration::from_secs(5), now);
    cache.insert("long.test", 80, address(80), Duration::from_secs(60), now);
    assert_eq!(cache.len(), 1);
    assert!(
        cache
            .lookup("short.test", 80, now + Duration::from_secs(1))
            .is_none()
    );
    assert!(
        cache
            .lookup("long.test", 80, now + Duration::from_secs(1))
            .is_some()
    );
}

#[test]
fn overrides_win_over_cached_answers_and_ip_literals() -> Result<()> {
    let options = cares::ResolverOptions::builder().build()?;
    let mut resolver =
        HostResolver::new(SubsystemId::new_unchecked(9), options, "127.0.0.1:53", 1)?;
    let now = Instant::now();
    let override_address = vec![SocketAddr::from(([192, 0, 2, 7], 443))];
    resolver.resolve_host(
        "Static.Example.",
        443,
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))],
    );
    assert_eq!(
        resolver.lookup_static_or_cache("static.example", 443, now),
        Some(override_address.clone())
    );
    assert_eq!(
        resolver.lookup_static_or_cache("127.0.0.1", 8080, now),
        Some(vec![SocketAddr::from(([127, 0, 0, 1], 8080))])
    );
    resolver.store_cache(
        "static.example",
        443,
        address(443),
        Duration::from_secs(60),
        now,
    );
    assert_eq!(
        resolver.lookup_static_or_cache("static.example", 443, now),
        Some(override_address)
    );
    resolver.resolve_host("static.example", 443, Vec::new());
    assert_eq!(
        resolver.lookup_static_or_cache("static.example", 443, now),
        Some(address(443))
    );
    resolver.clear_static("static.example", 443);
    assert!(
        resolver
            .lookup_static_or_cache("static.example", 443, now)
            .is_none()
    );
    Ok(())
}
