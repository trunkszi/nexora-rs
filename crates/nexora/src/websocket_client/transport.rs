//! Socket operands, tagged identities, and TLS wire-buffer helpers.

use uarch::prelude::*;

use super::*;
bitword! {
 struct WsTransportWord(u64) {
 [0..=51] pub SESSION: u64,
 [52..=55] pub TAG: u8,
 }
}
assert_layout!(WsTransportWord, size = 8, align = 8);

/// A socket address laid out as the `IORING_OP_CONNECT` operand.
pub(super) enum PeerAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl PeerAddr {
    pub(super) fn new(addr: SocketAddr) -> Self {
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

    pub(super) fn raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
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

/// Builds the callback handle used to stage inbox commands.
pub(super) fn client_context(inbox: &SubsystemInbox) -> ClientContext {
    inbox.context()
}

/// Queues wire bytes without moving the buffer a send currently references.
#[inline]
pub(super) fn push_wire(
    wire: &mut BytesMut,
    deferred: &mut BytesMut,
    in_flight: bool,
    bytes: &[u8],
) {
    if in_flight {
        deferred.extend_from_slice(bytes);
    } else {
        wire.extend_from_slice(bytes);
    }
}

/// Appends all queued TLS ciphertext to the wire buffers.
#[inline]
pub(super) fn drain_tls(
    tls: &mut TlsSession,
    wire: &mut BytesMut,
    deferred: &mut BytesMut,
    in_flight: bool,
) -> std::result::Result<(), ProtoError> {
    let mut chunk = BytesMut::with_capacity(TLS_CHUNK_SIZE);
    tls.take_ciphertext(&mut chunk)?;
    if !chunk.is_empty() {
        push_wire(wire, deferred, in_flight, &chunk);
    }
    Ok(())
}

/// Splits a completion payload into its tag and session identifier.
#[hot_inline]
pub(super) fn decode_op(payload: OperationPayload) -> (u64, u64) {
    let word = WsTransportWord::new(payload.raw());
    (
        word.get(WsTransportWord::TAG) as u64,
        word.get(WsTransportWord::SESSION),
    )
}

/// Packs one tagged session operation identifier.
#[inline]
pub(super) fn operation_id(
    subsystem: SubsystemId,
    tag: u64,
    id: WebSocketSessionId,
) -> OperationId {
    OperationId::pack(
        subsystem,
        OperationPayload::new_unchecked(
            WsTransportWord::default()
                .patch(
                    BitPatch::EMPTY
                        .with_field(WsTransportWord::TAG, tag & 0xf)
                        .with_field(WsTransportWord::SESSION, id.raw() & ID_MASK),
                )
                .raw(),
        ),
    )
}

/// Creates a non-blocking TCP descriptor for one address family.
pub(super) fn open_socket(addr: &SocketAddr) -> Result<RawFd> {
    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: `socket` takes only scalar arguments and returns a descriptor
    // owned by the caller. It is closed exactly once, either by `close_raw`
    // before any submission or by the io_uring close staged after all other
    // operations on it completed.
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

/// Closes a descriptor that has no submitted io_uring operation.
pub(super) fn close_raw(fd: RawFd) {
    if fd < 0 {
        return;
    }
    // SAFETY: The descriptor was created by `open_socket` and either never
    // submitted or already completed its connect, so this is its only close.
    unsafe { libc::close(fd) };
}

/// Rebuilds `errno` from a negative completion result.
#[cold_sink]
pub(super) fn io_error(result: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(result.saturating_neg())
}

/// Builds an invalid-state error.
#[cold_sink]
pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidState(reason.to_owned())
}

/// Produces a handshake nonce seed from the standard library's OS-seeded hasher.
pub(super) fn handshake_seed(id: WebSocketSessionId) -> u64 {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(id.raw());
    hasher.finish()
}

/// Reads nameservers from the system resolver configuration.
pub(super) fn system_servers_csv() -> String {
    const FALLBACK: &str = "127.0.0.1";
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        return String::from(FALLBACK);
    };
    let mut servers: Vec<String> = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(server) = fields.next() {
            servers.push(server.to_owned());
        }
    }
    if servers.is_empty() {
        String::from(FALLBACK)
    } else {
        servers.join(",")
    }
}
