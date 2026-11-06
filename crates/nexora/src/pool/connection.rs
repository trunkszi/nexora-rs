use super::*;

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
    /// Without TLS the plaintext is the wire form. With TLS, the `aws-lc-sys` adapter accepts
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

#[cfg(test)]
mod state_lifecycle {
    use super::{OriginState, OriginSuperstate};

    #[test]
    fn transitions_preserve_parallel_connections() {
        use OriginState::*;
        let states = [
            Idle,
            ResolvingDns,
            Connecting,
            Handshaking,
            ReadyHttp1,
            ReadyHttp2,
            Draining,
            Closed,
        ];
        let allowed = [0xff_u8, 0x87, 0xfd, 0xfd, 0xfd, 0xfd, 0xf9, 0xc7];
        for (row, state) in states.into_iter().enumerate() {
            for (column, next) in states.into_iter().enumerate() {
                assert_eq!(
                    state.can_transition_to(next),
                    allowed[row] & (1 << column) != 0,
                    "{state:?} -> {next:?}"
                );
            }
        }
        assert_eq!(ReadyHttp2.superstate(), OriginSuperstate::Ready);
        assert_eq!(Handshaking.superstate(), OriginSuperstate::Establishing);
        assert!(!Closed.can_transition_to(ReadyHttp1));
        assert!(!ResolvingDns.can_transition_to(ReadyHttp2));
    }
}
