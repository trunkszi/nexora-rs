//! Session completion handlers and socket plumbing for the WebSocket client.

use nexora_proto::Http1KeepAlive;

use super::*;

impl WebSocketClient {
    /// Routes one completion to the resolver or to its session state machine.
    pub(super) fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        let subsystem = completion.operation_id.subsystem_id();
        if subsystem == self.config.dns_subsystem {
            return self
                .dns
                .dispatch(completion, submissions)
                .map_err(Error::from);
        }
        if subsystem != self.config.net_subsystem {
            return Ok(());
        }
        submissions.claim_completion(completion)?;
        let (tag, raw) = decode_op(completion.operation_id.payload());
        if !(TAG_CONNECT..=TAG_PING_TIMEOUT).contains(&tag) {
            return Ok(());
        }
        let id = WebSocketSessionId::new(raw);
        let Some(mut owned) = self.sessions.remove(&id) else {
            return Ok(());
        };
        owned.inflight = owned.inflight.saturating_sub(1);
        match tag {
            TAG_CONNECT => self.on_connect(&mut owned, completion.result),
            TAG_RECV => self.on_recv(&mut owned, completion.result),
            TAG_SEND => self.on_send(&mut owned, completion.result),
            TAG_CLOSE => {
                owned.close_op = None;
                owned.fd = -1;
                owned.phase = SessionPhase::Closed;
            }
            TAG_CONNECT_TIMEOUT | TAG_PING_TIMEOUT => {
                self.on_timer(&mut owned, tag, completion.result)
            }
            _ => {}
        }
        if owned.phase != SessionPhase::Closed || owned.inflight != 0 {
            self.sessions.insert(id, owned);
        } else {
            self.handlers.remove(&id);
        }
        Ok(())
    }

    /// Handles the connect completion and starts TLS or the upgrade.
    fn on_connect(&mut self, session: &mut Session, result: i32) {
        session.connect_op = None;
        session.peer = None;
        // The deadline is disarmed whenever the attempt ends; its operand stays
        // owned until the timeout's own CQE.
        if let Some(op) = session.timer_op.take() {
            session.cancels.push(op);
        }
        if session.phase.is_teardown() {
            return;
        }
        if result < 0 {
            return self.fail(session, Error::Io(io_error(result)));
        }
        if !session.uri.scheme().is_tls() {
            return self.start_upgrade(session);
        }
        let Some(config) = self.config.tls_config.clone() else {
            return self.fail(
                session,
                invalid("a wss URL requires a TLS client configuration"),
            );
        };
        let host = session.uri.host().to_owned();
        match TlsSession::new_client(&config, &host) {
            Ok(tls) => {
                session.tls = Some(tls);
                session.phase = SessionPhase::Handshaking;
                self.drain_tls(session);
            }
            Err(error) => self.fail(session, Error::Proto(error)),
        }
    }

    /// Handles a receive completion and advances the protocol machines.
    fn on_recv(&mut self, session: &mut Session, result: i32) {
        session.recv_op = None;
        if session.phase.is_teardown() {
            return;
        }
        if result <= 0 {
            let error = if result == 0 {
                Error::ConnectionClosed
            } else {
                Error::Io(io_error(result))
            };
            return self.fail(session, error);
        }
        let read = result as usize;
        if read > session.rx.len() {
            return self.fail(session, invalid("receive completion exceeds the buffer"));
        }
        let mut failure = None;
        if let Some(tls) = session.tls.as_mut() {
            if let Err(error) = tls.feed_ciphertext(&session.rx[..read]) {
                failure = Some(error);
            } else {
                loop {
                    match tls.read_plaintext(&mut session.plain) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    }
                }
            }
        } else {
            session.plain.extend_from_slice(&session.rx[..read]);
        }
        if let Some(error) = failure {
            return self.fail(session, Error::Proto(error));
        }
        self.drain_tls(session);
        if session.phase == SessionPhase::Handshaking
            && session
                .tls
                .as_ref()
                .is_some_and(|tls| !tls.is_handshaking())
        {
            self.finish_handshake(session);
            if session.phase.is_teardown() {
                return;
            }
        }
        self.advance(session);
    }

    /// Handles a send completion and releases the transmitted prefix.
    fn on_send(&mut self, session: &mut Session, result: i32) {
        session.send_op = None;
        if result < 0 {
            if !session.phase.is_teardown() {
                self.fail(session, Error::Io(io_error(result)));
            }
            return;
        }
        if result == 0 {
            // A staged send carries at least one byte, so no progress means the
            // transport cannot deliver the queued data.
            return self.fail(session, Error::ConnectionClosed);
        }
        let sent = (result as usize).min(session.wire.len());
        session.wire.advance(sent);
        if session.wire.is_empty() && !session.deferred.is_empty() {
            let deferred = std::mem::take(&mut session.deferred);
            session.wire.extend_from_slice(&deferred);
        }
    }

    /// Handles a connect or keepalive deadline.
    fn on_timer(&mut self, session: &mut Session, tag: u64, result: i32) {
        drop(session.timer.take());
        session.timer_op = None;
        if session.phase.is_teardown() || result != -libc::ETIME {
            return;
        }
        match tag {
            TAG_CONNECT_TIMEOUT if session.phase == SessionPhase::Connecting => {
                if let Some(op) = session.connect_op.take() {
                    session.cancels.push(op);
                }
                self.fail(session, Error::Timeout);
            }
            TAG_PING_TIMEOUT if session.phase == SessionPhase::Open => {
                if let Err(error) = session.queue_message(WebSocketMessage::Ping(Bytes::new())) {
                    self.fail(session, Error::Proto(error));
                }
            }
            _ => {}
        }
    }

    /// Validates ALPN and starts the HTTP upgrade after the TLS handshake.
    fn finish_handshake(&mut self, session: &mut Session) {
        let alpn = session.tls.as_ref().and_then(|tls| tls.alpn_protocol());
        if alpn == Some(AlpnProtocol::Http2) {
            return self.fail(
                session,
                Error::Proto(ProtoError::Tls(String::from(
                    "the peer selected ALPN h2; a WebSocket upgrade requires http/1.1",
                ))),
            );
        }
        self.start_upgrade(session);
    }

    /// Queues the HTTP upgrade request.
    fn start_upgrade(&mut self, session: &mut Session) {
        let request =
            WebSocketHandshake::build_upgrade_request(&session.uri, &session.key, &session.extra);
        let mut bytes = BytesMut::with_capacity(256);
        let mut http = Http1ClientCodec::default();
        let encoded = http
            .encode_request(&request, &mut bytes)
            .and_then(|()| session.queue_app(&bytes));
        if let Err(error) = encoded {
            return self.fail(session, Error::Proto(error));
        }
        session.phase = SessionPhase::Upgrading;
    }

    /// Advances the HTTP upgrade or WebSocket message state machine.
    fn advance(&mut self, session: &mut Session) {
        if session.phase == SessionPhase::Upgrading {
            let mut http = Http1ClientCodec::default();
            match http.decode_response(&mut session.plain, Method::Get) {
                Ok(Some((response, Http1KeepAlive::Upgrade))) => {
                    if let Err(error) =
                        WebSocketHandshake::validate_upgrade_response(&response, &session.key)
                    {
                        return self.fail(session, Error::Proto(error));
                    }
                    session.phase = SessionPhase::Open;
                    if let Some(callback) = session.on_open.take() {
                        let mut ctx = client_context(&self.inbox);
                        callback(&mut ctx, session.id, Ok(()));
                    }
                }
                Ok(Some(_)) => {
                    return self.fail(
                        session,
                        Error::Proto(ProtoError::WebSocketProtocol(String::from(
                            "the server did not switch protocols",
                        ))),
                    );
                }
                Ok(None) => {}
                Err(error) => return self.fail(session, Error::Proto(error)),
            }
        }
        // Once either side has started the close handshake, further bytes are
        // not application data; decoding them would turn a peer's trailing junk
        // into a protocol failure that aborts the close reply still to be sent.
        if session.phase != SessionPhase::Open {
            return;
        }
        loop {
            match session.websocket.decode_message(&mut session.plain) {
                Ok(None) => return,
                Ok(Some(message)) => {
                    if !self.dispatch(session, message) {
                        return;
                    }
                }
                Err(error) => return self.fail(session, Error::Proto(error)),
            }
            if session.phase != SessionPhase::Open {
                return;
            }
        }
    }

    /// Handles one decoded message; returns whether decoding may continue.
    fn dispatch(&mut self, session: &mut Session, message: WebSocketMessage) -> bool {
        match message {
            WebSocketMessage::Text(text) => self.emit(session, WebSocketEvent::Text(text)),
            WebSocketMessage::Binary(data) => self.emit(session, WebSocketEvent::Binary(data)),
            WebSocketMessage::Ping(data) => {
                if let Err(error) = session.queue_message(WebSocketMessage::Pong(data.clone())) {
                    self.fail(session, Error::Proto(error));
                    return false;
                }
                self.emit(session, WebSocketEvent::Ping(data));
            }
            WebSocketMessage::Pong(data) => self.emit(session, WebSocketEvent::Pong(data)),
            WebSocketMessage::Close(close) => {
                // The codec rejects a second close frame, so a session that
                // already started the handshake only records the peer's reply.
                // RFC 6455 recommends mirroring the received status code.
                let echo = WebSocketCloseFrame {
                    code: close
                        .as_ref()
                        .map_or(WebSocketCloseCode::Normal, |frame| frame.code),
                    reason: String::new(),
                };
                let reply = !session.phase.is_closing();
                session.phase = SessionPhase::CloseFlush;
                self.emit(session, WebSocketEvent::Close(close));
                if reply
                    && let Err(error) = session.queue_message(WebSocketMessage::Close(Some(echo)))
                {
                    self.fail(session, Error::Proto(error));
                }
                return false;
            }
        }
        true
    }

    /// Delivers one event to the registered sink.
    fn emit(&mut self, session: &mut Session, event: WebSocketEvent) {
        if matches!(event, WebSocketEvent::Close(_)) && !session.phase.notify_close() {
            return;
        }
        let id = session.id;
        let Some(handler) = self.handlers.get_mut(&id) else {
            return;
        };
        let mut ctx = client_context(&self.inbox);
        let mut view = WebSocketSession { id };
        handler(&mut ctx, &mut view, event);
    }

    /// Reports a terminal error and starts teardown.
    pub(super) fn fail(&mut self, session: &mut Session, error: Error) {
        if session.phase.is_teardown() {
            return;
        }
        match session.on_open.take() {
            Some(callback) => {
                let mut ctx = client_context(&self.inbox);
                callback(&mut ctx, session.id, Err(error));
            }
            None => self.emit(session, WebSocketEvent::Close(None)),
        }
        // A lookup still in flight will never be applied to this session.
        if let Some(lookup) = session.lookup.take() {
            self.dns_waiters.remove(&lookup);
        }
        session.phase.begin_teardown();
    }

    /// Stages pending cancels, sends, receives, timers, and teardown work.
    pub(super) fn pump(&mut self, proactor: &mut Proactor) -> Result<()> {
        let mut sessions = std::mem::take(&mut self.sessions);
        let mut failure: Option<Error> = None;
        for (id, mut session) in sessions.drain() {
            if let Err(error) = self.pump_session(&mut session, proactor)
                && failure.is_none()
            {
                failure = Some(error);
            }
            if session.phase != SessionPhase::Closed || session.inflight != 0 {
                self.sessions.insert(id, session);
            } else {
                self.handlers.remove(&id);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Stages the next operation for one session.
    fn pump_session(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        if session.phase == SessionPhase::Closed {
            return Ok(());
        }
        self.stage_cancels(session, proactor)?;
        if session.phase.is_teardown() {
            return self.pump_close(session, proactor);
        }
        if session.send_op.is_none() && !session.wire.is_empty() {
            self.stage_send(session, proactor)?;
        }
        let framed = matches!(
            session.phase,
            SessionPhase::Handshaking | SessionPhase::Upgrading | SessionPhase::Open
        );
        // A closing session needs no more peer bytes: the remaining work is the
        // close reply already on the wire, and continuing to receive would grow
        // `plain` with data that the codec must reject.
        if framed && session.recv_op.is_none() {
            self.stage_recv(session, proactor)?;
        }
        let keepalive = self
            .config
            .ping_interval
            .is_some_and(|interval| !interval.is_zero());
        if session.phase == SessionPhase::Open
            && keepalive
            && session.timer.is_none()
            && session.timer_op.is_none()
        {
            self.stage_ping_timer(session, proactor)?;
        }
        if session.phase.is_closing()
            && session.send_op.is_none()
            && session.wire.is_empty()
            && session.deferred.is_empty()
        {
            session.phase.begin_teardown();
            self.pump_close(session, proactor)?;
        }
        Ok(())
    }

    /// Stages every queued cancellation and tracks the resulting completions.
    fn stage_cancels(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        let targets = std::mem::take(&mut session.cancels);
        for target in targets {
            match stage_cancel(proactor, self.config.net_subsystem, target) {
                Ok(()) => session.inflight += 1,
                Err(error) => {
                    session.cancels.push(target);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Cancels outstanding work and closes the descriptor once it is idle.
    fn pump_close(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        let mut targets: Vec<OperationId> = [
            session.recv_op.take(),
            session.send_op.take(),
            session.connect_op.take(),
            session.timer_op.take(),
        ]
        .into_iter()
        .flatten()
        .collect();
        targets.append(&mut session.cancels);
        for target in targets {
            match stage_cancel(proactor, self.config.net_subsystem, target) {
                Ok(()) => session.inflight += 1,
                Err(error) => {
                    session.cancels.push(target);
                    return Err(error);
                }
            }
        }
        if session.inflight != 0 {
            return Ok(());
        }
        if session.fd < 0 || session.close_op.is_some() {
            if session.close_op.is_none() {
                session.phase = SessionPhase::Closed;
            }
            return Ok(());
        }
        let fd = session.fd;
        let op = operation_id(self.config.net_subsystem, TAG_CLOSE, session.id);
        proactor.prepare_sqe_with(op, |sqe| {
            // SAFETY: This is the only close submitted for `fd`: every earlier
            // operation on it delivered its final CQE because `inflight`
            // reached zero, so close ownership transfers exactly once.
            unsafe { net::prep_close(sqe, fd) }
        })?;
        session.close_op = Some(op);
        session.inflight += 1;
        session.fd = -1;
        Ok(())
    }

    /// Stages one receive into the session's fixed buffer.
    fn stage_recv(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        let fd = session.fd;
        if fd < 0 {
            return Ok(());
        }
        let op = operation_id(self.config.net_subsystem, TAG_RECV, session.id);
        let ptr = session.rx.as_mut_ptr();
        let len = session.rx.len();
        proactor.prepare_sqe_with(op, |sqe| {
            // SAFETY: `rx` is a fixed-address heap allocation owned by the
            // session and is never resized, reused, or freed until this
            // receive's final CQE has been observed.
            unsafe { net::prep_recv(sqe, fd, ptr, len, 0) }
        })?;
        session.recv_op = Some(op);
        session.inflight += 1;
        Ok(())
    }

    /// Stages one send of the queued wire prefix.
    fn stage_send(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        let fd = session.fd;
        if fd < 0 || session.wire.is_empty() {
            return Ok(());
        }
        let op = operation_id(self.config.net_subsystem, TAG_SEND, session.id);
        let ptr = session.wire.as_slice().as_ptr();
        let len = session.wire.len();
        proactor.prepare_sqe_with(op, |sqe| {
            // SAFETY: While `send_op` is set, `queue_app` appends new bytes to
            // `deferred`, so this buffer's pointer and length stay valid and
            // readable until the final send CQE. `MSG_NOSIGNAL` keeps a peer
            // reset from raising SIGPIPE.
            unsafe { net::prep_send(sqe, fd, ptr, len, libc::MSG_NOSIGNAL) }
        })?;
        session.send_op = Some(op);
        session.inflight += 1;
        Ok(())
    }

    /// Stages one keepalive deadline.
    fn stage_ping_timer(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        let Some(interval) = self
            .config
            .ping_interval
            .filter(|interval| !interval.is_zero())
        else {
            return Ok(());
        };
        let timeout = Timeout::new(interval)?;
        let op = operation_id(self.config.net_subsystem, TAG_PING_TIMEOUT, session.id);
        proactor.prepare_sqe_with(op, |sqe| {
            // SAFETY: The `Timeout` owner stays in `session.timer` until its
            // own final CQE, including after cancellation.
            unsafe { timeout.prepare(sqe) }
        })?;
        session.timer = Some(timeout);
        session.timer_op = Some(op);
        session.inflight += 1;
        Ok(())
    }

    /// Moves queued TLS output into the wire buffers, failing the session on error.
    fn drain_tls(&mut self, session: &mut Session) {
        let outcome = {
            let Session {
                tls,
                wire,
                deferred,
                send_op,
                ..
            } = &mut *session;
            tls.as_mut()
                .map(|tls| drain_tls(tls, wire, deferred, send_op.is_some()))
        };
        if let Some(Err(error)) = outcome {
            self.fail(session, Error::Proto(error));
        }
    }

    /// Applies completed family lookups to their sessions.
    pub(super) fn apply_dns(&mut self, proactor: &mut Proactor) -> Result<usize> {
        let mut applied = 0;
        loop {
            let popped = self
                .dns_outcomes
                .try_borrow_mut()
                .ok()
                .and_then(|mut queue| queue.pop_front());
            let Some((lookup, addrs, error)) = popped else {
                break;
            };
            applied += 1;
            let Some(id) = self.dns_waiters.get(&lookup).copied() else {
                continue;
            };
            let Some(mut owned) = self.sessions.remove(&id) else {
                self.dns_waiters.remove(&lookup);
                continue;
            };
            if owned.lookup != Some(lookup) {
                self.dns_waiters.remove(&lookup);
                self.sessions.insert(id, owned);
                continue;
            }
            owned.dns_left = owned.dns_left.saturating_sub(1);
            if let Some(error) = error
                && owned.dns_reason.is_none()
            {
                owned.dns_reason = Some(error);
            }
            if let Some(addr) = addrs.first().copied() {
                owned.lookup = None;
                owned.phase = SessionPhase::Connecting;
                self.sessions.insert(id, owned);
                self.dns_waiters.remove(&lookup);
                // The drive loop has no caller to return this error to, so the
                // open callback is the only place the failure can surface.
                if let Err(error) = self.begin_connect(proactor, id, addr)
                    && let Some(mut failed) = self.sessions.remove(&id)
                {
                    self.fail(&mut failed, error);
                    self.sessions.insert(id, failed);
                }
            } else if owned.dns_left == 0 {
                owned.lookup = None;
                let host = owned.uri.host().to_owned();
                let reason = owned
                    .dns_reason
                    .take()
                    .unwrap_or_else(|| String::from("no records"));
                self.fail(&mut owned, Error::DnsResolutionFailed { host, reason });
                self.dns_waiters.remove(&lookup);
                self.sessions.insert(id, owned);
            } else {
                self.sessions.insert(id, owned);
            }
        }
        Ok(applied)
    }
}

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
pub(super) fn decode_op(payload: OperationPayload) -> (u64, u64) {
    let raw = payload.raw();
    (raw >> TAG_SHIFT, raw & ID_MASK)
}

/// Packs one tagged session operation identifier.
pub(super) fn operation_id(
    subsystem: SubsystemId,
    tag: u64,
    id: WebSocketSessionId,
) -> OperationId {
    OperationId::pack(
        subsystem,
        OperationPayload::new_unchecked((tag << TAG_SHIFT) | (id.raw() & ID_MASK)),
    )
}

/// Stages cancellation of one target operation.
pub(super) fn stage_cancel(
    proactor: &mut Proactor,
    subsystem: SubsystemId,
    target: OperationId,
) -> Result<()> {
    // A cancel completion still routes to the session that owned the target,
    // so its payload carries the session id rather than the target's tag.
    let session = WebSocketSessionId::new(target.payload().raw() & ID_MASK);
    let op = operation_id(subsystem, TAG_CANCEL, session);
    proactor.prepare_sqe_with(op, |sqe| {
        // SAFETY: Cancellation matches the target's exact user-data key and
        // references no buffer. The target's storage stays alive in the session
        // until its final CQE, which is counted in `inflight`.
        unsafe { net::prep_cancel(sqe, target, 0) }
    })?;
    Ok(())
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
pub(super) fn io_error(result: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(result.saturating_neg())
}

/// Builds an invalid-state error.
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
