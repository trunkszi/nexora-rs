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

/// Lifecycle of one origin inside the pool.
///
/// The state is per origin, not per connection: an origin may already be
/// [`OriginState::ReadyHttp1`] while another of its connections is still
/// [`OriginState::Connecting`] or [`OriginState::Handshaking`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// A resolving origin must pass through [`OriginState::Connecting`], and a
    /// closed or draining origin cannot jump straight to a ready state, so a
    /// late completion cannot resurrect a shut-down origin.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn can_transition_to(self, next: Self) -> bool {
        use OriginState::{
            Closed, Connecting, Draining, Handshaking, Idle, ReadyHttp1, ReadyHttp2, ResolvingDns,
        };
        match self {
            Idle => true,
            ResolvingDns => matches!(next, ResolvingDns | Connecting | Idle | Closed),
            Connecting => matches!(
                next,
                Connecting | Handshaking | ReadyHttp1 | ReadyHttp2 | Idle | Closed | Draining
            ),
            Handshaking => matches!(
                next,
                Handshaking | Connecting | ReadyHttp1 | ReadyHttp2 | Idle | Closed | Draining
            ),
            ReadyHttp1 | ReadyHttp2 => matches!(
                next,
                ReadyHttp1 | ReadyHttp2 | Handshaking | Connecting | Idle | Closed | Draining
            ),
            Draining => matches!(
                next,
                Draining | Handshaking | ReadyHttp1 | ReadyHttp2 | Idle | Closed
            ),
            Closed => matches!(next, Closed | Idle | Connecting | ResolvingDns | Draining),
        }
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

impl Connection {
    /// Creates a connecting socket with pinned buffers.
    pub(crate) fn new(
        id: u64,
        key: OriginKey,
        fd: RawFd,
        addr: SocketAddr,
        limits: ConnectionLimits,
    ) -> Self {
        let http2 = (limits.http2_prior_knowledge && key.scheme == Scheme::Http).then(|| {
            Http2Connection::new(
                Http2Role::Client,
                Http2Config {
                    max_body_size: limits.max_body_size,
                    ..Http2Config::default()
                },
            )
        });
        Self {
            id,
            key,
            fd,
            peer: Some(Box::new(PeerAddr::new(addr))),
            kind: ConnKind::Connecting,
            tls: None,
            rx: vec![0u8; RX_BUFFER].into_boxed_slice(),
            rx_op: None,
            out: BytesMut::with_capacity(4096),
            tx_pending: BytesMut::with_capacity(4096),
            tx_inflight: BytesMut::with_capacity(1),
            send_op: None,
            connect_op: None,
            close_op: None,
            plain: BytesMut::with_capacity(4096),
            h1: Http1ClientCodec::new(Http1ClientConfig {
                max_header_list_size: limits.max_header_list_size,
                max_body_size: limits.max_body_size,
                max_request_body_size: limits.max_request_body_size,
            }),
            http2,
            current: None,
            streams: HashMap::new(),
            in_flight_ops: 0,
            want_close: false,
        }
    }

    /// Moves queued HTTP/2 frames into the plaintext output and encrypts them.
    pub(crate) fn drain_http2(&mut self) -> std::result::Result<(), ProtoError> {
        if let Some(http2) = self.http2.as_mut() {
            http2.take_tx_bytes(&mut self.out);
        }
        self.pump()
    }

    /// Encrypts plaintext output and moves it into the writable send buffer.
    ///
    /// Without TLS the plaintext is the wire form. With TLS, `rustls` accepts
    /// only part of a record-sized write, so the unwritten tail stays queued for
    /// the next pump.
    pub(crate) fn pump(&mut self) -> std::result::Result<(), ProtoError> {
        match self.tls.as_mut() {
            Some(session) => {
                if !self.out.is_empty() {
                    let written = session.write_plaintext(&self.out)?;
                    self.out.advance(written.min(self.out.len()));
                }
                session.take_ciphertext(&mut self.tx_pending)?;
            }
            None => {
                self.tx_pending.extend_from_slice(&self.out);
                self.out.clear();
            }
        }
        Ok(())
    }

    /// Stages whatever this connection needs next, deferring close until every
    /// submitted operation has delivered its final completion.
    pub(crate) fn flush(
        &mut self,
        proactor: &mut Proactor,
        subsystem: SubsystemId,
        ops: &mut HashMap<u64, OpKind>,
    ) -> Result<()> {
        if self.close_op.is_some() {
            return Ok(());
        }
        if self.want_close {
            if self.in_flight_ops == 0 {
                stage_close(proactor, subsystem, ops, self)?;
            }
            return Ok(());
        }
        if self.kind == ConnKind::Connecting {
            return if self.connect_op.is_none() {
                stage_connect(proactor, subsystem, ops, self)
            } else {
                Ok(())
            };
        }
        if matches!(self.kind, ConnKind::Http1 | ConnKind::Http2) {
            if self.rx_op.is_none() {
                stage_recv(proactor, subsystem, ops, self)?;
            }
            if self.send_op.is_none()
                && !(self.tx_pending.is_empty() && self.tx_inflight.is_empty())
            {
                stage_send(proactor, subsystem, ops, self)?;
            }
        }
        Ok(())
    }

    /// Feeds one completed receive through TLS and then the protocol decoder.
    pub(crate) fn ingest(&mut self, len: usize) -> IngestOutcome {
        let Some(session) = self.tls.as_mut() else {
            self.plain.extend_from_slice(&self.rx[..len]);
            return IngestOutcome::NeedMore;
        };
        if let Err(error) = session.feed_ciphertext(&self.rx[..len]) {
            return IngestOutcome::Failed(error);
        }
        loop {
            match session.read_plaintext(&mut self.plain) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) => return IngestOutcome::Failed(error),
            }
        }
        if let Err(error) = session.take_ciphertext(&mut self.tx_pending) {
            return IngestOutcome::Failed(error);
        }
        if self.kind == ConnKind::Handshaking && !session.is_handshaking() {
            return IngestOutcome::Ready(session.alpn_protocol());
        }
        IngestOutcome::NeedMore
    }
}

/// Creates a non-blocking, close-on-exec stream socket for `addr`.
pub(crate) fn open_socket(addr: &SocketAddr) -> Result<RawFd> {
    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: `socket` borrows no storage; the descriptor is owned by the
    // connection and closed through io_uring exactly once.
    let fd = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Closes a descriptor that the ring no longer owns.
pub(crate) fn close_raw(fd: RawFd) {
    // SAFETY: The caller owns the descriptor and has established that no close
    // operation was submitted for it, so this is its only close.
    unsafe { libc::close(fd) };
}

/// Stages the CONNECT described by the connection's boxed peer address.
pub(crate) fn stage_connect(
    proactor: &mut Proactor,
    subsystem: SubsystemId,
    ops: &mut HashMap<u64, OpKind>,
    conn: &mut Connection,
) -> Result<()> {
    let token = next_token();
    let id = operation_id(subsystem, token)?;
    let Some(peer) = conn.peer.as_ref() else {
        return Err(Error::InvalidState(String::from(
            "connection has no peer address",
        )));
    };
    let (addr, len) = peer.raw();
    // SAFETY: The boxed peer address stays alive inside the connection until the
    // CONNECT completes, and the connection owns the descriptor.
    proactor.prepare_sqe_with(id, |sqe| unsafe {
        net::prep_connect(sqe, conn.fd, addr, len)
    })?;
    ops.insert(token, OpKind::Connect(conn.id));
    conn.connect_op = Some(id);
    conn.in_flight_ops += 1;
    Ok(())
}

/// Stages a receive into the connection's pinned buffer.
pub(crate) fn stage_recv(
    proactor: &mut Proactor,
    subsystem: SubsystemId,
    ops: &mut HashMap<u64, OpKind>,
    conn: &mut Connection,
) -> Result<()> {
    let token = next_token();
    let id = operation_id(subsystem, token)?;
    let buffer = conn.rx.as_mut_ptr();
    let len = conn.rx.len();
    // SAFETY: The boxed receive buffer is owned by the connection and is neither
    // resized nor freed before this operation's final completion.
    proactor.prepare_sqe_with(id, |sqe| unsafe {
        net::prep_recv(sqe, conn.fd, buffer, len, 0)
    })?;
    ops.insert(token, OpKind::Recv(conn.id));
    conn.rx_op = Some(id);
    conn.in_flight_ops += 1;
    Ok(())
}

/// Stages a send of everything currently queued.
pub(crate) fn stage_send(
    proactor: &mut Proactor,
    subsystem: SubsystemId,
    ops: &mut HashMap<u64, OpKind>,
    conn: &mut Connection,
) -> Result<()> {
    let token = next_token();
    let id = operation_id(subsystem, token)?;
    if conn.tx_inflight.is_empty() {
        conn.tx_inflight = conn.tx_pending.split_to(conn.tx_pending.len());
    }
    let pointer = conn.tx_inflight.as_slice().as_ptr();
    let len = conn.tx_inflight.len();
    // SAFETY: Writes to the shared storage detach it, so this pointer stays valid
    // and `tx_inflight` is not mutated until the send completes.
    proactor.prepare_sqe_with(id, |sqe| unsafe {
        net::prep_send(sqe, conn.fd, pointer, len, 0)
    })?;
    ops.insert(token, OpKind::Send(conn.id));
    conn.send_op = Some(id);
    conn.in_flight_ops += 1;
    Ok(())
}

/// Stages the descriptor close once no operation references it.
pub(crate) fn stage_close(
    proactor: &mut Proactor,
    subsystem: SubsystemId,
    ops: &mut HashMap<u64, OpKind>,
    conn: &mut Connection,
) -> Result<()> {
    let token = next_token();
    let id = operation_id(subsystem, token)?;
    // SAFETY: Every operation referencing this descriptor has delivered its final
    // completion, and ownership of the descriptor transfers to this close.
    proactor.prepare_sqe_with(id, |sqe| unsafe { net::prep_close(sqe, conn.fd) })?;
    ops.insert(token, OpKind::Close(conn.id));
    conn.close_op = Some(id);
    conn.in_flight_ops += 1;
    Ok(())
}

/// Cancels one submitted operation by its kernel identity.
pub(crate) fn stage_cancel(
    proactor: &mut Proactor,
    subsystem: SubsystemId,
    target: OperationId,
) -> Result<()> {
    let token = next_token();
    // SAFETY: Cancellation matches the target's operation key only; the target's
    // storage remains retained until its own final completion arrives.
    proactor.prepare_sqe_with(operation_id(subsystem, token)?, |sqe| unsafe {
        net::prep_cancel(sqe, target, 0)
    })?;
    Ok(())
}

impl Drop for Connection {
    fn drop(&mut self) {
        // A receive, send, or connect operation keeps a raw pointer into the
        // matching buffer until its final completion arrives. Leaking the
        // allocation is the only safe action while that completion is pending;
        // the pointer may even belong to a staged SQE that was never submitted.
        if self.rx_op.is_some() {
            std::mem::forget(std::mem::replace(&mut self.rx, Box::new([])));
        }
        if self.send_op.is_some() {
            std::mem::forget(std::mem::take(&mut self.tx_inflight));
        }
        if self.connect_op.is_some() {
            std::mem::forget(self.peer.take());
        }
        // A close completion owns the descriptor from submission onwards, and an
        // outstanding operation keeps it referenced. Closing here would either
        // double-close or let a later submission target a recycled file.
        if self.close_op.is_none() {
            if self.in_flight_ops == 0 {
                close_raw(self.fd);
            } else {
                // SAFETY: This connection retains the descriptor while the ring
                // references it. Shutdown changes socket state without releasing
                // its number or the buffers retained for final completions.
                unsafe { libc::shutdown(self.fd, libc::SHUT_RDWR) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, os::fd::RawFd};

    use nexora_proto::Scheme;

    use super::*;

    fn socket_pair() -> (RawFd, RawFd) {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` points to two writable slots that `socketpair` fills.
        let result =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(result, 0, "socketpair failed");
        (fds[0], fds[1])
    }

    fn connection_over(fd: RawFd) -> Connection {
        Connection::new(
            1,
            OriginKey::new(Scheme::Http, "drop.test", 80),
            fd,
            SocketAddr::from(([127, 0, 0, 1], 80)),
            ConnectionLimits {
                max_header_list_size: 1024,
                max_body_size: 1024,
                max_request_body_size: usize::MAX,
                http2_prior_knowledge: false,
            },
        )
    }

    fn fd_is_open(fd: RawFd) -> bool {
        // SAFETY: `fcntl` only inspects the descriptor number and writes nothing.
        unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
    }

    fn close_fd(fd: RawFd) {
        // SAFETY: The descriptor is owned by this test and closed exactly once here.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn drop_closes_a_descriptor_with_no_outstanding_operation() {
        let (fd, peer) = socket_pair();
        drop(connection_over(fd));
        assert!(!fd_is_open(fd), "drop must close an idle descriptor");
        close_fd(peer);
    }

    #[test]
    fn drop_retains_the_descriptor_while_a_receive_is_outstanding() -> Result<()> {
        let (fd, peer) = socket_pair();
        let mut conn = connection_over(fd);
        conn.rx = vec![0u8; 8].into_boxed_slice();
        conn.rx_op = Some(operation_id(SubsystemId::new_unchecked(1), next_token())?);
        conn.in_flight_ops = 1;
        drop(conn);
        assert!(fd_is_open(fd), "the ring still references the descriptor");
        let mut byte = 0u8;
        // SAFETY: `peer` is a live socket and `byte` is writable for one byte.
        let received = unsafe {
            libc::recv(
                peer,
                std::ptr::from_mut(&mut byte).cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        };
        assert_eq!(
            received, 0,
            "drop must notify the peer without recycling the fd"
        );
        close_fd(fd);
        close_fd(peer);
        Ok(())
    }

    #[test]
    fn drop_leaves_a_staged_close_to_the_ring() -> Result<()> {
        let (fd, peer) = socket_pair();
        let mut conn = connection_over(fd);
        conn.close_op = Some(operation_id(SubsystemId::new_unchecked(1), next_token())?);
        conn.in_flight_ops = 1;
        drop(conn);
        assert!(fd_is_open(fd), "the close completion owns the descriptor");
        close_fd(fd);
        close_fd(peer);
        Ok(())
    }
}
