//! Per-origin connection, waiter, and DNS-query bookkeeping for the HTTP client.
//!
//! [`OriginPool`] is a passive state container: it performs no I/O and owns no
//! sockets. The client registers connection tokens, records lifecycle
//! transitions, and asks the pool for work, while the pool keeps waiters
//! coalesced per origin and enforces the configured connection limits.
//!
//! Waiters stay queued while DNS resolution or the first handshake is in
//! flight. They are deduplicated by [`RequestId`] and drained in submission
//! order by [`OriginPool::take_waiters`] when an origin fails outright, so each
//! waiting request receives its terminal callback exactly once.

use std::{
    cell::Cell,
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    os::fd::RawFd,
    time::{Duration, Instant},
};

use cares::QueryHandle;
use liburing::{OperationId, OperationPayload, Proactor, SubsystemId, ops::net};
use nexora_proto::{
    BytesMut, Http1ClientCodec, Http1ClientConfig, Http2Config, Http2Connection, Http2Role,
    ProtoError, Scheme, TlsSession,
};
use uarch::{
    mem::{L1, prefetch_read},
    prelude::*,
};

use crate::{
    error::{Error, Result},
    inbox::RequestId,
};

/// Identity of a connection origin: scheme, host, and TCP port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OriginKey {
    /// Application scheme, which separates TLS from cleartext origins.
    pub scheme: Scheme,
    /// Lowercase host without IPv6 brackets.
    pub host: String,
    /// Explicit port or the scheme default.
    pub port: u16,
}

impl OriginKey {
    /// Builds an origin key from its three components.
    ///
    /// The host is normalized to ASCII lowercase, stripped of IPv6 brackets,
    /// and stripped of one trailing dot, matching [`crate::dns::DnsCache`], so
    /// equivalent spellings share one origin. Struct literals bypass this
    /// normalization.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(scheme: Scheme, host: impl Into<String>, port: u16) -> Self {
        let host: String = host.into();
        let lowered = host.to_ascii_lowercase();
        let unbracketed = lowered
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(lowered.as_str());
        let host = match unbracketed.strip_suffix('.') {
            Some(stripped) => stripped.to_owned(),
            None => unbracketed.to_owned(),
        };
        Self { scheme, host, port }
    }

    /// Builds the key for an absolute URI, using its effective port.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn from_uri(uri: &nexora_proto::Uri) -> Self {
        Self::new(uri.scheme(), uri.host(), uri.port())
    }

    /// Returns the `host:port` string, bracketing an IPv6 host so the result
    /// is valid as an HTTP `Host` header value.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn authority(&self) -> String {
        let host = &self.host;
        let port = self.port;
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }
}

/// Limits applied to every origin managed by an [`OriginPool`].
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections_per_origin: usize,
    pub max_idle_per_origin: usize,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    /// Six connections, six idle, 90 s idle timeout, five minute lifetime.
    fn default() -> Self {
        Self {
            max_connections_per_origin: 6,
            max_idle_per_origin: 6,
            idle_timeout: Duration::from_secs(90),
            max_lifetime: Duration::from_secs(300),
        }
    }
}

/// Shared lifecycle guards for origin connection phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OriginSuperstate {
    Idle,
    Establishing,
    Ready,
    Draining,
    Closed,
}

/// Lifecycle of one origin inside the pool.
///
/// The state is per origin, not per connection: an origin may already be
/// [`OriginState::ReadyHttp1`] while another of its connections is still
/// [`OriginState::Connecting`] or [`OriginState::Handshaking`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OriginState {
    #[default]
    Idle,
    ResolvingDns,
    Connecting,
    Handshaking,
    ReadyHttp1,
    ReadyHttp2,
    Draining,
    Closed,
}

impl OriginState {
    /// Reports whether a direct transition from `self` to `next` is legal.
    ///
    /// [`OriginState::Idle`] accepts every state because a fresh origin may
    /// begin at any phase, and an origin whose connections were opened in
    /// parallel can already be ready while another connection completes.
    /// A resolving origin must pass through [`OriginState::Connecting`]. Closed
    /// origins reject ready completions; draining origins may still accept a
    /// parallel handshake that was already admitted.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn can_transition_to(self, next: Self) -> bool {
        const TRANSITIONS: [u8; 8] = [0xff, 0x87, 0xfd, 0xfd, 0xfd, 0xfd, 0xf9, 0xc7];
        TRANSITIONS[self as usize] & (1 << next as u8) != 0
    }

    /// Returns the shared lifecycle guard for this origin phase.
    pub const fn superstate(self) -> OriginSuperstate {
        const PARENTS: [OriginSuperstate; 8] = [
            OriginSuperstate::Idle,
            OriginSuperstate::Establishing,
            OriginSuperstate::Establishing,
            OriginSuperstate::Establishing,
            OriginSuperstate::Ready,
            OriginSuperstate::Ready,
            OriginSuperstate::Draining,
            OriginSuperstate::Closed,
        ];
        PARENTS[self as usize]
    }
}

/// One connection owned by the client and tracked by the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PooledConnection {
    pub connection: u64,
    pub created: Instant,
    pub idle_since: Option<Instant>,
    pub streams: usize,
    /// Set by [`OriginPool::mark_busy`] and cleared by
    /// [`OriginPool::mark_idle`]. A busy connection is never evicted.
    busy: bool,
}

/// Pool state for a single origin.
#[derive(Debug, Default)]
pub struct OriginEntry {
    pub state: OriginState,
    pub waiters: VecDeque<RequestId>,
    pub connections: Vec<PooledConnection>,
    pub query_handles: Vec<QueryHandle>,
    pub candidate_ips: VecDeque<SocketAddr>,
}

/// Outcome of [`OriginPool::remove_waiter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaiterRemoval {
    NotWaiting,
    Removed,
    RemovedLast,
}

/// Connection, waiter, and DNS state keyed by origin.
pub struct OriginPool {
    config: PoolConfig,
    origins: HashMap<OriginKey, OriginEntry>,
}

mod origin;

impl Default for OriginPool {
    /// Uses [`PoolConfig::default`].
    fn default() -> Self {
        Self::new(PoolConfig::default())
    }
}

/// Receive buffer size per connection.
const RX_BUFFER: usize = 64 * 1024;

/// Socket completion classification, keyed by the operation token.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OpKind {
    Connect(u64),
    Recv(u64),
    Send(u64),
    Close(u64),
    Timer(u64),
}

thread_local! {
    static NEXT_OP_TOKEN: Cell<u64> = const { Cell::new(1) };
}

/// Reserves a thread-local operation token, so clients sharing one ring
/// never misroute each other's completions.
pub(crate) fn next_token() -> u64 {
    NEXT_OP_TOKEN.with(|next| {
        let token = next.get();
        next.set(token.wrapping_add(1));
        token
    })
}

/// Packs a routing subsystem and an operation token into kernel user data.
pub(crate) fn operation_id(subsystem: SubsystemId, token: u64) -> Result<OperationId> {
    let payload = OperationPayload::new(token)
        .ok_or_else(|| Error::InvalidState(String::from("operation token exceeds 56 bits")))?;
    Ok(OperationId::pack(subsystem, payload))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnKind {
    Connecting,
    Handshaking,
    Http1,
    Http2,
    Closed,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConnectionLimits {
    pub max_header_list_size: usize,
    pub max_body_size: usize,
    pub max_request_body_size: usize,
    pub http2_prior_knowledge: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum IngestOutcome {
    NeedMore,
    Ready(Option<nexora_proto::AlpnProtocol>),
    Failed(ProtoError),
}

/// Kernel socket address kept at a stable address until its CONNECT completes.
enum PeerAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl PeerAddr {
    fn new(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4(libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            }),
            SocketAddr::V6(v6) => Self::V6(libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            }),
        }
    }

    fn raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(value) => (
                std::ptr::from_ref(value).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Self::V6(value) => (
                std::ptr::from_ref(value).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

pub(crate) struct Connection {
    pub(crate) id: u64,
    pub(crate) key: OriginKey,
    pub(crate) fd: RawFd,
    peer: Option<Box<PeerAddr>>,
    pub(crate) kind: ConnKind,
    pub(crate) tls: Option<TlsSession>,
    rx: Box<[u8]>,
    pub(crate) rx_op: Option<OperationId>,
    pub(crate) out: BytesMut,
    pub(crate) tx_pending: BytesMut,
    pub(crate) tx_inflight: BytesMut,
    pub(crate) send_op: Option<OperationId>,
    pub(crate) connect_op: Option<OperationId>,
    pub(crate) close_op: Option<OperationId>,
    pub(crate) plain: BytesMut,
    pub(crate) h1: Http1ClientCodec,
    pub(crate) http2: Option<Http2Connection>,
    pub(crate) current: Option<RequestId>,
    pub(crate) streams: HashMap<u32, RequestId>,
    pub(crate) in_flight_ops: usize,
    pub(crate) want_close: bool,
}

#[inline]
fn matching_slots(
    chunk: &[PooledConnection],
    accept: impl Fn(&PooledConnection) -> bool,
) -> Bitmap64 {
    let mut slots = Bitmap64::EMPTY;
    for (index, connection) in chunk.iter().enumerate() {
        if accept(connection) {
            slots = slots.set(index as u32);
        }
    }
    slots
}

mod connection;
#[cfg(test)]
pub(crate) use connection::stage_close;
pub(crate) use connection::{close_raw, open_socket, stage_cancel, stage_recv, stage_send};
