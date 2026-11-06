//! Session completion handlers and socket plumbing for the WebSocket client.

use nexora_proto::Http1KeepAlive;

pub(super) use super::transport::{
    PeerAddr, client_context, close_raw, decode_op, drain_tls, handshake_seed, invalid, io_error,
    open_socket, operation_id, push_wire, system_servers_csv,
};
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
        let id = if tag == TAG_CANCEL {
            let Some(owner) = self.cancel_owners.remove(&completion.operation_id) else {
                return Ok(());
            };
            owner
        } else {
            WebSocketSessionId::new(raw)
        };
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
                if completion.result == -libc::ECANCELED {
                    owned.state.begin_teardown();
                } else {
                    owned.fd = -1;
                    owned.state.set_phase(SessionPhase::Closed);
                }
            }
            TAG_CONNECT_TIMEOUT | TAG_PING_TIMEOUT => {
                self.on_timer(&mut owned, tag, completion.result)
            }
            _ => {}
        }
        if owned.state.phase() != SessionPhase::Closed || owned.inflight != 0 {
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
        if session.state.phase().is_teardown() {
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
                session.state.set_phase(SessionPhase::Handshaking);
                self.drain_tls(session);
            }
            Err(error) => self.fail(session, Error::Proto(error)),
        }
    }

    /// Handles a receive completion and advances the protocol machines.
    fn on_recv(&mut self, session: &mut Session, result: i32) {
        session.recv_op = None;
        if session.state.phase().is_teardown() {
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
        if session.state.phase() == SessionPhase::Handshaking
            && session
                .tls
                .as_ref()
                .is_some_and(|tls| !tls.is_handshaking())
        {
            self.finish_handshake(session);
            if session.state.phase().is_teardown() {
                return;
            }
        }
        self.advance(session);
    }

    /// Handles a send completion and releases the transmitted prefix.
    fn on_send(&mut self, session: &mut Session, result: i32) {
        session.send_op = None;
        if result < 0 {
            if !session.state.phase().is_teardown() {
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
        if session.state.phase().is_teardown() || result != -libc::ETIME {
            return;
        }
        match tag {
            TAG_CONNECT_TIMEOUT if session.state.phase() == SessionPhase::Connecting => {
                if let Some(op) = session.connect_op.take() {
                    session.cancels.push(op);
                }
                self.fail(session, Error::Timeout);
            }
            TAG_PING_TIMEOUT if session.state.phase() == SessionPhase::Open => {
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
        session.state.set_phase(SessionPhase::Upgrading);
    }

    /// Advances the HTTP upgrade or WebSocket message state machine.
    fn advance(&mut self, session: &mut Session) {
        if session.state.phase() == SessionPhase::Upgrading {
            let mut http = Http1ClientCodec::default();
            match http.decode_response(&mut session.plain, Method::Get) {
                Ok(Some((response, Http1KeepAlive::Upgrade))) => {
                    if let Err(error) =
                        WebSocketHandshake::validate_upgrade_response(&response, &session.key)
                    {
                        return self.fail(session, Error::Proto(error));
                    }
                    session.state.set_phase(SessionPhase::Open);
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
        if session.state.phase() != SessionPhase::Open {
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
            if session.state.phase() != SessionPhase::Open {
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
                let reply = !session.state.phase().is_closing();
                session.state.set_phase(SessionPhase::CloseFlush);
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
        if matches!(event, WebSocketEvent::Close(_)) && !session.state.notify_close() {
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
        if session.state.phase().is_teardown() {
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
        session.state.begin_teardown();
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
            if session.state.phase() != SessionPhase::Closed || session.inflight != 0 {
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
        if session.state.phase() == SessionPhase::Closed {
            return Ok(());
        }
        self.stage_cancels(session, proactor)?;
        if session.state.phase().is_teardown() {
            return self.pump_close(session, proactor);
        }
        if session.send_op.is_none() && !session.wire.is_empty() {
            self.stage_send(session, proactor)?;
        }
        let framed = matches!(
            session.state.phase(),
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
        if session.state.phase() == SessionPhase::Open
            && keepalive
            && session.timer.is_none()
            && session.timer_op.is_none()
        {
            self.stage_ping_timer(session, proactor)?;
        }
        if session.state.phase().is_closing()
            && session.send_op.is_none()
            && session.wire.is_empty()
            && session.deferred.is_empty()
        {
            session.state.begin_teardown();
            self.pump_close(session, proactor)?;
        }
        Ok(())
    }

    fn stage_cancel(
        &mut self,
        session: &mut Session,
        proactor: &mut Proactor,
        target: OperationId,
    ) -> Result<()> {
        let token = self
            .next_cancel
            .checked_add(1)
            .filter(|token| *token <= ID_MASK)
            .ok_or_else(|| invalid("cancellation identities exhausted"))?;
        // Each control CQE needs its own identity while preserving its session owner.
        let op = operation_id(
            self.config.net_subsystem,
            TAG_CANCEL,
            WebSocketSessionId::new(token),
        );
        proactor.prepare_sqe_with(op, |sqe| {
            // SAFETY: Cancellation refers to the target identity only. Its operands
            // remain retained until the target's final CQE retires its in-flight count.
            unsafe { net::prep_cancel(sqe, target, 0) }
        })?;
        self.next_cancel = token;
        self.cancel_owners.insert(op, session.id);
        session.inflight += 1;
        Ok(())
    }

    /// Retains each cancellation target until its control SQE is accepted.
    fn stage_cancels(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        while let Some(&target) = session.cancels.last() {
            self.stage_cancel(session, proactor, target)?;
            session.cancels.pop();
        }
        Ok(())
    }

    /// Cancels outstanding work and closes the descriptor once it is idle.
    fn pump_close(&mut self, session: &mut Session, proactor: &mut Proactor) -> Result<()> {
        session.cancels.extend(
            [
                session.recv_op.take(),
                session.send_op.take(),
                session.connect_op.take(),
                session.timer_op.take(),
            ]
            .into_iter()
            .flatten(),
        );
        self.stage_cancels(session, proactor)?;
        if session.inflight != 0 {
            return Ok(());
        }
        if session.fd < 0 || session.close_op.is_some() {
            if session.close_op.is_none() {
                session.state.set_phase(SessionPhase::Closed);
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
            owned
                .state
                .set_dns_left(owned.state.dns_left().saturating_sub(1));
            if let Some(error) = error
                && owned.dns_reason.is_none()
            {
                owned.dns_reason = Some(error);
            }
            if let Some(addr) = addrs.first().copied() {
                owned.lookup = None;
                owned.state.set_phase(SessionPhase::Connecting);
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
            } else if owned.state.dns_left() == 0 {
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
