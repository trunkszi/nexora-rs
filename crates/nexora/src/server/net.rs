//! Listening socket, peer address, and plaintext-to-ciphertext queueing.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
};

use liburing::{OperationId, OperationPayload, SubsystemId};

use super::model::{Conn, Mode};
use crate::{Error, Result, SocketState};

pub(super) fn conn_mut(conns: &mut [Option<Conn>], slot: usize) -> Option<&mut Conn> {
    conns.get_mut(slot)?.as_mut()
}

pub(super) fn want_recv(conn: &Conn, shutdown: bool) -> bool {
    if conn.recv_on || conn.close_pending || conn.close_on || conn.mode == Mode::Dead {
        return false;
    }
    if conn.sock.state() != SocketState::Connected {
        return false;
    }
    if conn.outstanding == 0 && (conn.http_close || shutdown) {
        return false;
    }
    true
}

pub(super) fn queue_out(conn: &mut Conn, bytes: &[u8]) -> Result<()> {
    if !conn.sock.has_tls() {
        conn.pending.extend_from_slice(bytes);
        return Ok(());
    }
    let Some(mut tls) = conn.sock.take_tls() else {
        return Err(Error::InvalidState(String::from("missing TLS session")));
    };
    let mut offset = 0;
    let mut error = None;
    while offset < bytes.len() {
        match tls.write_plaintext(&bytes[offset..]) {
            Ok(0) => {
                error = Some(Error::InvalidState(String::from(
                    "TLS accepted no plaintext",
                )));
                break;
            }
            Ok(n) => offset += n,
            Err(err) => {
                error = Some(Error::from(err));
                break;
            }
        }
        if let Err(err) = tls.take_ciphertext(&mut conn.pending) {
            error = Some(Error::from(err));
            break;
        }
    }
    if error.is_none()
        && let Err(err) = tls.take_ciphertext(&mut conn.pending)
    {
        error = Some(Error::from(err));
    }
    conn.sock.set_tls(tls);
    match error {
        Some(err) => {
            conn.mode = Mode::Dead;
            conn.http_close = true;
            Err(err)
        }
        None => Ok(()),
    }
}

pub(super) fn preface_decision(buf: &[u8]) -> Option<bool> {
    let preface = crate::proto::http2::CLIENT_PREFACE;
    if buf.is_empty() {
        return None;
    }
    if buf.len() < preface.len() {
        return if preface.starts_with(buf) {
            None
        } else {
            Some(false)
        };
    }
    Some(buf.starts_with(preface))
}

pub(super) fn pack(subsystem: SubsystemId, kind: u64, slot: u32) -> OperationId {
    OperationId::pack(
        subsystem,
        OperationPayload::new_unchecked((kind << 32) | u64::from(slot)),
    )
}

pub(super) fn unpack(id: OperationId) -> (u64, u32) {
    let raw = id.payload().raw();
    let kind = raw >> 32;
    let slot = u32::try_from(raw & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    (kind, slot)
}

pub(super) fn blank_addr() -> libc::sockaddr_storage {
    // SAFETY: `sockaddr_storage` is a C aggregate of integers. The all-zero
    // value is a valid bit pattern and is overwritten before accept completes.
    unsafe { std::mem::zeroed() }
}

pub(super) fn listen(addr: SocketAddr, backlog: i32) -> Result<(RawFd, SocketAddr)> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: `socket` allocates a new descriptor. The flags request close-on-exec
    // and non-blocking mode at creation.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    if let Err(error) = configure_listener(fd, addr, backlog) {
        // SAFETY: `socket` succeeded and no other owner has observed `fd`.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    match local_address(fd) {
        Ok(local) => Ok((fd, local)),
        Err(error) => {
            // SAFETY: configuration failed after the descriptor was created, and
            // this function is still its only owner.
            unsafe { libc::close(fd) };
            Err(error)
        }
    }
}

pub(super) fn configure_listener(fd: RawFd, addr: SocketAddr, backlog: i32) -> Result<()> {
    let yes = 1i32;
    // SAFETY: `fd` is a live socket owned by the caller. `yes` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            std::ptr::from_ref(&yes).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<i32>()).unwrap_or(0),
        )
    };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    bind_socket(fd, addr)?;
    // SAFETY: `fd` is a bound socket owned by the caller.
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(super) fn bind_socket(fd: RawFd, addr: SocketAddr) -> Result<()> {
    let rc = match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `fd` is a live socket and `sa` is a valid IPv4 address for this call.
            unsafe {
                libc::bind(
                    fd,
                    std::ptr::from_ref(&sa).cast(),
                    libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())
                        .unwrap_or(0),
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: `fd` is a live socket and `sa` is a valid IPv6 address for this call.
            unsafe {
                libc::bind(
                    fd,
                    std::ptr::from_ref(&sa).cast(),
                    libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in6>())
                        .unwrap_or(0),
                )
            }
        }
    };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(super) fn local_address(fd: RawFd) -> Result<SocketAddr> {
    let mut storage = blank_addr();
    let mut len =
        libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>()).unwrap_or(0);
    // SAFETY: `fd` is a live socket. `storage` and `len` are writable for this call.
    let rc = unsafe { libc::getsockname(fd, std::ptr::addr_of_mut!(storage).cast(), &mut len) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    sockaddr_to_std(&storage, len)
}

pub(super) fn sockaddr_to_std(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Result<SocketAddr> {
    if storage.ss_family == libc::AF_INET as libc::sa_family_t
        && usize::try_from(u64::from(len)).unwrap_or(0) >= std::mem::size_of::<libc::sockaddr_in>()
    {
        // SAFETY: the family and length match `sockaddr_in`, and the kernel wrote `storage`.
        let v4 = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
        let ip = Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr));
        return Ok(SocketAddr::V4(SocketAddrV4::new(
            ip,
            u16::from_be(v4.sin_port),
        )));
    }
    if storage.ss_family == libc::AF_INET6 as libc::sa_family_t
        && usize::try_from(u64::from(len)).unwrap_or(0) >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        // SAFETY: the family and length match `sockaddr_in6`, and the kernel wrote `storage`.
        let v6 = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
        let ip = Ipv6Addr::from(v6.sin6_addr.s6_addr);
        return Ok(SocketAddr::V6(SocketAddrV6::new(
            ip,
            u16::from_be(v6.sin6_port),
            v6.sin6_flowinfo,
            v6.sin6_scope_id,
        )));
    }
    Err(Error::InvalidState(String::from(
        "unsupported socket address family",
    )))
}
