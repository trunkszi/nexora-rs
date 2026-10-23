//! HTTP/1, HTTP/2, TLS, and WebSocket demux on one accepted socket.

use std::{cell::Cell, net::SocketAddr, rc::Rc};

use super::{
    model::{Mode, State},
    net::{conn_mut, preface_decision, queue_out},
    service::{HttpService, RequestContext, Responder},
};
use crate::{
    Error, Result, StatusCode, Version, WebSocketMessage, WebSocketSessionId,
    inbox::{DeferredResponse, InboxCommand},
    proto::{
        AlpnProtocol, Bytes, BytesMut, Http1KeepAlive, Http2Config, Http2Connection,
        Http2ErrorCode, Http2Event, Http2Role, ProtoError, Request, Response, TlsSession,
        WebSocketCodec, WebSocketHandshake,
    },
    websocket_server::WebSocketServerSession,
};

impl<S: HttpService> State<S> {
    pub(super) fn pump_all(&mut self) -> Result<()> {
        let slots: Vec<usize> = (0..self.conns.len()).collect();
        for slot in slots {
            self.pump_slot(slot)?;
        }
        Ok(())
    }

    pub(super) fn pump_slot(&mut self, slot: usize) -> Result<()> {
        self.ingest(slot)?;
        if self.mode_of(slot) == Mode::Sniff {
            self.classify(slot)?;
        }
        let pumped = match self.mode_of(slot) {
            Mode::Http1 => self.http1_pump(slot),
            Mode::Http2 => self.http2_pump(slot),
            Mode::WebSocket | Mode::Sniff | Mode::Dead => Ok(()),
        };
        let websocket = if self.mode_of(slot) == Mode::WebSocket {
            self.websocket_pump(slot)
        } else {
            Ok(())
        };
        // A failed feed queues GOAWAY on the codec before returning. Pull
        // those bytes even when the pump already failed.
        let pulled = self.pull_http2(slot);
        pumped?;
        websocket?;
        pulled
    }

    pub(super) fn mode_of(&self, slot: usize) -> Mode {
        self.conns
            .get(slot)
            .and_then(|slot| slot.as_ref())
            .map(|conn| conn.mode)
            .unwrap_or(Mode::Dead)
    }

    pub(super) fn ingest(&mut self, slot: usize) -> Result<()> {
        let install = self
            .conns
            .get(slot)
            .and_then(|slot| slot.as_ref())
            .is_some_and(|conn| {
                conn.mode == Mode::Sniff
                    && !conn.sock.has_tls()
                    && conn.raw.as_ref().first() == Some(&0x16)
            });
        if install
            && let Some(config) = self.config.tls.clone()
            && let Some(conn) = conn_mut(&mut self.conns, slot)
        {
            conn.sock.set_tls(TlsSession::new_server(&config)?);
        }
        let has_tls = self
            .conns
            .get(slot)
            .and_then(|slot| slot.as_ref())
            .is_some_and(|conn| conn.sock.has_tls());
        if has_tls {
            return self.decrypt(slot);
        }
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            let raw = conn.raw.as_ref().to_vec();
            conn.raw.clear();
            conn.plain.extend_from_slice(&raw);
        }
        Ok(())
    }

    pub(super) fn decrypt(&mut self, slot: usize) -> Result<()> {
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Ok(());
        };
        let Some(mut tls) = conn.sock.take_tls() else {
            return Err(Error::InvalidState(String::from("missing TLS session")));
        };
        let mut error = None;
        match tls.feed_ciphertext(conn.raw.as_ref()) {
            Ok(_available) => conn.raw.clear(),
            Err(err) => error = Some(Error::from(err)),
        }
        if error.is_none()
            && let Err(err) = tls.read_plaintext(&mut conn.plain)
        {
            error = Some(Error::from(err));
        }
        if error.is_none()
            && let Err(err) = tls.take_ciphertext(&mut conn.pending)
        {
            error = Some(Error::from(err));
        }
        conn.sock.set_tls(tls);
        match error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    pub(super) fn classify(&mut self, slot: usize) -> Result<()> {
        let (alpn, handshaking, buf) = {
            let Some(conn) = self.conns.get(slot).and_then(|slot| slot.as_ref()) else {
                return Ok(());
            };
            let alpn = conn.sock.tls().and_then(TlsSession::alpn_protocol);
            let handshaking = conn.sock.tls().is_some_and(TlsSession::is_handshaking);
            (alpn, handshaking, conn.plain.as_ref().to_vec())
        };
        if handshaking {
            return Ok(());
        }
        let is_http2 = match alpn {
            Some(AlpnProtocol::Http2) => true,
            Some(AlpnProtocol::Http11) => false,
            None => match preface_decision(&buf) {
                Some(value) => value,
                None => return Ok(()),
            },
        };
        if is_http2 {
            self.start_http2(slot)
        } else if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.mode = Mode::Http1;
            Ok(())
        } else {
            Ok(())
        }
    }

    pub(super) fn start_http2(&mut self, slot: usize) -> Result<()> {
        let max_body_size = self.config.max_body_size;
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Ok(());
        };
        let mut http2 = Http2Connection::new(
            Http2Role::Server,
            Http2Config {
                max_body_size,
                ..Http2Config::default()
            },
        );
        if let Err(error) = http2.feed_bytes(&mut conn.plain) {
            let mut staged = BytesMut::new();
            http2.take_tx_bytes(&mut staged);
            let staged = staged.as_ref().to_vec();
            conn.mode = Mode::Dead;
            conn.http_close = true;
            // The codec has not been stored yet. GOAWAY lives only on this
            // local connection until it is copied into the socket queue.
            queue_out(conn, &staged)?;
            return Err(Error::from(error));
        }
        conn.http2 = Some(http2);
        conn.mode = Mode::Http2;
        Ok(())
    }

    pub(super) fn http1_pump(&mut self, slot: usize) -> Result<()> {
        loop {
            let outstanding = self
                .conns
                .get(slot)
                .and_then(|slot| slot.as_ref())
                .map(|conn| conn.outstanding)
                .unwrap_or(0);
            let closing = self
                .conns
                .get(slot)
                .and_then(|slot| slot.as_ref())
                .is_some_and(|conn| conn.http_close);
            if outstanding > 0 || closing || self.mode_of(slot) != Mode::Http1 {
                return Ok(());
            }
            let decoded = {
                let Some(conn) = conn_mut(&mut self.conns, slot) else {
                    return Ok(());
                };
                conn.http1.decode_request(&mut conn.plain)
            };
            match decoded {
                Ok(None) => return Ok(()),
                Ok(Some((request, keep_alive))) => {
                    if keep_alive == Http1KeepAlive::Close
                        && let Some(conn) = conn_mut(&mut self.conns, slot)
                    {
                        conn.http_close = true;
                    }
                    if self.maybe_upgrade(slot, &request)? {
                        return Ok(());
                    }
                    self.dispatch(slot, request, None)?;
                }
                Err(ProtoError::BodyTooLarge { .. }) => {
                    self.reject(slot, StatusCode::PAYLOAD_TOO_LARGE, b"Payload Too Large")?;
                }
                Err(ProtoError::Http1Protocol(message))
                    if message.contains("direction is closed") =>
                {
                    if let Some(conn) = conn_mut(&mut self.conns, slot) {
                        conn.http_close = true;
                    }
                    return Ok(());
                }
                Err(_) => self.reject(slot, StatusCode::BAD_REQUEST, b"Bad Request")?,
            }
        }
    }

    pub(super) fn maybe_upgrade(&mut self, slot: usize, request: &Request) -> Result<bool> {
        if self.websocket.is_none()
            || self.websocket_path.is_empty()
            || request.path() != self.websocket_path
        {
            return Ok(false);
        }
        let key = match WebSocketHandshake::validate_upgrade_request(request) {
            Ok(key) => key,
            Err(_) => {
                self.reject(slot, StatusCode::BAD_REQUEST, b"Bad Request")?;
                return Ok(true);
            }
        };
        self.write_response(slot, None, WebSocketHandshake::build_upgrade_response(&key))?;
        let id = self.inbox.next_websocket_session_id();
        let peer = self
            .conns
            .get(slot)
            .and_then(|slot| slot.as_ref())
            .and_then(|conn| conn.sock.peer_addr());
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.mode = Mode::WebSocket;
            conn.websocket = Some(WebSocketCodec::server_default());
            conn.websocket_id = Some(id);
        }
        self.open_websocket(slot, id, peer)?;
        Ok(true)
    }

    pub(super) fn http2_pump(&mut self, slot: usize) -> Result<()> {
        let feed_error = {
            let Some(conn) = conn_mut(&mut self.conns, slot) else {
                return Ok(());
            };
            match conn.http2.as_mut() {
                Some(http2) => http2.feed_bytes(&mut conn.plain).err(),
                None => None,
            }
        };
        if let Some(error) = feed_error {
            self.fail_conn(slot);
            return Err(Error::from(error));
        }
        self.pull_http2(slot)?;
        loop {
            let event =
                conn_mut(&mut self.conns, slot).and_then(|conn| conn.http2.as_mut()?.poll_event());
            let Some(event) = event else {
                break;
            };
            self.on_http2(slot, event)?;
            self.pull_http2(slot)?;
        }
        Ok(())
    }

    pub(super) fn on_http2(&mut self, slot: usize, event: Http2Event) -> Result<()> {
        match event {
            Http2Event::RequestReceived { stream_id, request } => {
                if request.body.len() > self.config.max_body_size {
                    self.write_status(
                        slot,
                        Some(stream_id),
                        StatusCode::PAYLOAD_TOO_LARGE,
                        b"Payload Too Large",
                    )?;
                } else {
                    self.dispatch(slot, request, Some(stream_id))?;
                }
            }
            Http2Event::StreamReset { stream_id, .. } => self.finish_stream(slot, Some(stream_id)),
            Http2Event::StreamBodyTooLarge { stream_id, .. } => {
                self.write_status(
                    slot,
                    Some(stream_id),
                    StatusCode::PAYLOAD_TOO_LARGE,
                    b"Payload Too Large",
                )?;
            }
            Http2Event::GoAwayReceived { .. } => {
                if let Some(conn) = conn_mut(&mut self.conns, slot) {
                    conn.http_close = true;
                }
            }
            Http2Event::ResponseReceived { .. }
            | Http2Event::SettingsAcknowledged
            | Http2Event::PingAcknowledged(_) => {}
        }
        Ok(())
    }

    pub(super) fn websocket_pump(&mut self, slot: usize) -> Result<()> {
        loop {
            let decoded = {
                let Some(conn) = conn_mut(&mut self.conns, slot) else {
                    return Ok(());
                };
                let Some(codec) = conn.websocket.as_mut() else {
                    return Ok(());
                };
                codec.decode_message(&mut conn.plain)
            };
            match decoded {
                Ok(None) => return Ok(()),
                Ok(Some(message)) => self.dispatch_websocket(slot, message)?,
                Err(error) => {
                    self.note_websocket_error(slot, &Error::from(error));
                    self.fail_conn(slot);
                    return Ok(());
                }
            }
        }
    }

    pub(super) fn dispatch(
        &mut self,
        slot: usize,
        request: Request,
        stream: Option<u32>,
    ) -> Result<()> {
        let Some(conn) = self.conns.get(slot).and_then(|slot| slot.as_ref()) else {
            return Err(Error::ConnectionClosed);
        };
        let (id, peer, version) = (conn.id, conn.sock.peer_addr(), request.version);
        let gate = Rc::new(Cell::new(true));
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.gates.push((stream, Rc::clone(&gate)));
            conn.outstanding = conn.outstanding.saturating_add(1);
        }
        let responder = Responder::live(self.inbox.clone(), id, stream, gate);
        let mut ctx = RequestContext {
            peer,
            params: Vec::new(),
            version,
            stream_id: stream,
        };
        let result = self.service.call(&mut ctx, request, responder);
        self.drain_inbox()?;
        if let Err(error) = result {
            self.fail_conn(slot);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn drain_inbox(&mut self) -> Result<()> {
        loop {
            let Some(command) = self.inbox.pop() else {
                break;
            };
            match command {
                InboxCommand::Respond(response) => self.apply_response(response)?,
                InboxCommand::WebSocketSend {
                    session_id,
                    message,
                } => {
                    self.enqueue_websocket(session_id, message)?;
                }
                InboxCommand::WebSocketClose { session_id, close } => {
                    self.enqueue_websocket(session_id, WebSocketMessage::Close(close))?;
                }
                InboxCommand::Submit(_)
                | InboxCommand::Cancel(_)
                | InboxCommand::SetTimer(_)
                | InboxCommand::DnsResolved(_) => {}
            }
        }
        Ok(())
    }

    pub(super) fn apply_response(&mut self, deferred: DeferredResponse) -> Result<()> {
        let Some(slot) = self.slot_of_id(deferred.connection_id) else {
            return Ok(());
        };
        let stream = deferred.stream_id;
        if self
            .write_response(slot, stream, deferred.response)
            .is_err()
        {
            self.finish_stream(slot, stream);
            self.fail_conn(slot);
            return Ok(());
        }
        self.finish_stream(slot, stream);
        Ok(())
    }

    pub(super) fn write_response(
        &mut self,
        slot: usize,
        stream: Option<u32>,
        mut response: Response,
    ) -> Result<()> {
        let mode = self.mode_of(slot);
        if self.shutting_down
            && mode == Mode::Http1
            && response.status != StatusCode::SWITCHING_PROTOCOLS
        {
            response
                .headers
                .insert(String::from("connection"), String::from("close"));
        }
        match mode {
            Mode::Http2 => self.write_http2(slot, stream, &response),
            Mode::Http1 | Mode::Sniff => self.write_h1(slot, &mut response),
            Mode::WebSocket | Mode::Dead => Ok(()),
        }
    }

    pub(super) fn write_http2(
        &mut self,
        slot: usize,
        stream: Option<u32>,
        response: &Response,
    ) -> Result<()> {
        let Some(stream_id) = stream else {
            return Ok(());
        };
        {
            let Some(conn) = conn_mut(&mut self.conns, slot) else {
                return Ok(());
            };
            let Some(http2) = conn.http2.as_mut() else {
                return Ok(());
            };
            match http2.submit_response(stream_id, response) {
                Ok(()) => {}
                Err(ProtoError::Http2StreamError { .. }) => return Ok(()),
                Err(error) => return Err(Error::from(error)),
            }
        }
        self.pull_http2(slot)
    }

    pub(super) fn write_h1(&mut self, slot: usize, response: &mut Response) -> Result<()> {
        if !matches!(response.version, Version::Http10 | Version::Http11) {
            response.version = Version::Http11;
        }
        let bytes = {
            let Some(conn) = conn_mut(&mut self.conns, slot) else {
                return Ok(());
            };
            let mut out = BytesMut::new();
            conn.http1.encode_response(response, &mut out)?;
            out.as_ref().to_vec()
        };
        let close_after = response
            .headers
            .get("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close"));
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Ok(());
        };
        if close_after {
            conn.http_close = true;
        }
        queue_out(conn, &bytes)
    }

    pub(super) fn write_status(
        &mut self,
        slot: usize,
        stream: Option<u32>,
        status: StatusCode,
        body: &'static [u8],
    ) -> Result<()> {
        // The limit applies to the request. An error body longer than that
        // limit still has to be encoded, so the response falls back to empty.
        let body = if body.len() <= self.config.max_body_size {
            body
        } else {
            b""
        };
        self.write_response(
            slot,
            stream,
            Response::text(status, Bytes::from_static(body)),
        )
    }

    pub(super) fn reject(
        &mut self,
        slot: usize,
        status: StatusCode,
        body: &'static [u8],
    ) -> Result<()> {
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.plain.clear();
            conn.http_close = true;
        }
        self.write_status(slot, None, status, body)
    }

    pub(super) fn pull_http2(&mut self, slot: usize) -> Result<()> {
        let bytes = {
            let Some(conn) = conn_mut(&mut self.conns, slot) else {
                return Ok(());
            };
            let Some(http2) = conn.http2.as_mut() else {
                return Ok(());
            };
            if !http2.has_tx_bytes() {
                return Ok(());
            }
            let mut tmp = BytesMut::new();
            http2.take_tx_bytes(&mut tmp);
            tmp.as_ref().to_vec()
        };
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Ok(());
        };
        queue_out(conn, &bytes)
    }

    pub(super) fn open_websocket(
        &mut self,
        slot: usize,
        id: WebSocketSessionId,
        peer: Option<SocketAddr>,
    ) -> Result<()> {
        let mut session = WebSocketServerSession::for_test(id, peer);
        let mut handler = self.websocket.take();
        if let Some(handler) = handler.as_mut()
            && let Err(error) = handler.on_open(&mut session)
        {
            handler.on_error(&mut session, &error);
        }
        self.websocket = handler;
        self.flush_session(slot, &mut session)
    }

    pub(super) fn dispatch_websocket(
        &mut self,
        slot: usize,
        message: WebSocketMessage,
    ) -> Result<()> {
        let (id, peer) = {
            let Some(conn) = self.conns.get(slot).and_then(|slot| slot.as_ref()) else {
                return Ok(());
            };
            (
                conn.websocket_id.unwrap_or(WebSocketSessionId::new(0)),
                conn.sock.peer_addr(),
            )
        };
        let mut session = WebSocketServerSession::for_test(id, peer);
        if let WebSocketMessage::Ping(payload) = &message {
            session.send(WebSocketMessage::Pong(payload.clone()))?;
        }
        let mut handler = self.websocket.take();
        if let Some(handler) = handler.as_mut() {
            let result = match &message {
                WebSocketMessage::Close(frame) => handler.on_close(&mut session, frame.clone()),
                other => handler.on_message(&mut session, other.clone()),
            };
            if let Err(error) = result {
                handler.on_error(&mut session, &error);
            }
        }
        self.websocket = handler;
        if matches!(message, WebSocketMessage::Close(_))
            && !session.has_close()
            && let WebSocketMessage::Close(frame) = message
        {
            session.close(frame)?;
        }
        if session.has_close()
            && let Some(conn) = conn_mut(&mut self.conns, slot)
        {
            conn.http_close = true;
        }
        self.flush_session(slot, &mut session)
    }

    pub(super) fn flush_session(
        &mut self,
        slot: usize,
        session: &mut WebSocketServerSession,
    ) -> Result<()> {
        for message in session.take_outbound() {
            self.encode_websocket(slot, &message)?;
        }
        Ok(())
    }

    pub(super) fn note_websocket_error(&mut self, slot: usize, error: &Error) {
        let (id, peer) = {
            let Some(conn) = self.conns.get(slot).and_then(|slot| slot.as_ref()) else {
                return;
            };
            (
                conn.websocket_id.unwrap_or(WebSocketSessionId::new(0)),
                conn.sock.peer_addr(),
            )
        };
        let mut session = WebSocketServerSession::for_test(id, peer);
        let mut handler = self.websocket.take();
        if let Some(handler) = handler.as_mut() {
            handler.on_error(&mut session, error);
        }
        self.websocket = handler;
        if self.flush_session(slot, &mut session).is_err() {
            self.fail_conn(slot);
        }
    }

    pub(super) fn encode_websocket(
        &mut self,
        slot: usize,
        message: &WebSocketMessage,
    ) -> Result<()> {
        let bytes = {
            let Some(conn) = conn_mut(&mut self.conns, slot) else {
                return Err(Error::ConnectionClosed);
            };
            let Some(codec) = conn.websocket.as_mut() else {
                return Err(Error::InvalidState(String::from(
                    "connection is not a websocket",
                )));
            };
            let mut out = BytesMut::new();
            codec.encode_message(message, &mut out)?;
            out.as_ref().to_vec()
        };
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Err(Error::ConnectionClosed);
        };
        queue_out(conn, &bytes)
    }

    pub(super) fn enqueue_websocket(
        &mut self,
        session_id: WebSocketSessionId,
        message: WebSocketMessage,
    ) -> Result<()> {
        let Some(slot) = self.slot_of_websocket(session_id) else {
            return Err(Error::ConnectionClosed);
        };
        let closing = matches!(message, WebSocketMessage::Close(_));
        self.encode_websocket(slot, &message)?;
        if closing && let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.http_close = true;
        }
        Ok(())
    }

    pub(super) fn graceful(&mut self, slot: usize) -> Result<()> {
        let is_http2 = self.mode_of(slot) == Mode::Http2;
        if is_http2 {
            if let Some(conn) = conn_mut(&mut self.conns, slot)
                && let Some(http2) = conn.http2.as_mut()
            {
                match http2.send_goaway(0x7fff_ffff, Http2ErrorCode::NoError, Bytes::new()) {
                    Ok(()) | Err(ProtoError::Http2ConnectionError { .. }) => {}
                    Err(error) => return Err(Error::from(error)),
                }
            }
            self.pull_http2(slot)?;
        }
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.http_close = true;
        }
        Ok(())
    }
}
