//! Session protocol state and retained descriptor, buffer, and TLS ownership.

use super::*;

/// Connection state of one WebSocket session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    Resolving,
    Connecting,
    Handshaking,
    Upgrading,
    Open,
    Closed,
}

/// One completed family query: lookup ticket, addresses, failure text.
pub(super) type DnsOutcome = (u64, Vec<SocketAddr>, Option<String>);

/// Owned state of one connection attempt or established WebSocket.
pub(super) struct Session {
    pub(super) id: WebSocketSessionId,
    pub(super) uri: Uri,
    pub(super) state: State,
    pub(super) fd: RawFd,
    pub(super) peer: Option<Box<PeerAddr>>,
    pub(super) tls: Option<TlsSession>,
    pub(super) websocket: WebSocketCodec,
    pub(super) key: String,
    pub(super) extra: Headers,
    pub(super) plain: BytesMut,
    pub(super) rx: Box<[u8]>,
    pub(super) wire: BytesMut,
    pub(super) deferred: BytesMut,
    pub(super) send_op: Option<OperationId>,
    pub(super) recv_op: Option<OperationId>,
    pub(super) connect_op: Option<OperationId>,
    pub(super) close_op: Option<OperationId>,
    pub(super) cancels: Vec<OperationId>,
    pub(super) timer: Option<Timeout>,
    pub(super) timer_op: Option<OperationId>,
    pub(super) inflight: usize,
    pub(super) closing: bool,
    pub(super) teardown: bool,
    pub(super) close_event_sent: bool,
    pub(super) lookup: Option<u64>,
    pub(super) dns_left: u8,
    pub(super) dns_reason: Option<String>,
    pub(super) on_open: Option<OpenCallback>,
}
impl Session {
    pub(super) fn new(
        id: WebSocketSessionId,
        uri: Uri,
        config: &WebSocketClientConfig,
        extra: Headers,
        key: String,
        on_open: OpenCallback,
    ) -> Self {
        let websocket = WebSocketCodec::new(
            WebSocketRole::Client,
            WebSocketConfig {
                max_frame_size: config.max_frame_size,
                max_message_size: config.max_message_size,
            },
        );
        Self {
            id,
            uri,
            state: State::Resolving,
            fd: -1,
            peer: None,
            tls: None,
            websocket,
            key,
            extra,
            plain: BytesMut::with_capacity(4096),
            rx: vec![0_u8; RX_BUFFER_SIZE].into_boxed_slice(),
            wire: BytesMut::with_capacity(4096),
            deferred: BytesMut::with_capacity(1024),
            send_op: None,
            recv_op: None,
            connect_op: None,
            close_op: None,
            cancels: Vec::new(),
            timer: None,
            timer_op: None,
            inflight: 0,
            closing: false,
            teardown: false,
            close_event_sent: false,
            lookup: None,
            dns_left: 0,
            dns_reason: None,
            on_open: Some(on_open),
        }
    }
    pub(super) fn queue_message(
        &mut self,
        message: WebSocketMessage,
    ) -> std::result::Result<(), ProtoError> {
        let mut bytes = BytesMut::with_capacity(64);
        self.websocket.encode_message(&message, &mut bytes)?;
        self.queue_app(&bytes)
    }
    pub(super) fn queue_app(&mut self, bytes: &[u8]) -> std::result::Result<(), ProtoError> {
        if self.tls.is_none() {
            let in_flight = self.send_op.is_some();
            push_wire(&mut self.wire, &mut self.deferred, in_flight, bytes);
            return Ok(());
        }
        let mut rest = bytes;
        for _ in 0..MAX_WRITE_ROUNDS {
            if rest.is_empty() {
                return Ok(());
            }
            let Some(tls) = self.tls.as_mut() else {
                return Ok(());
            };
            let accepted = tls.write_plaintext(rest)?;
            if accepted == 0 {
                break;
            }
            rest = &rest[accepted..];
            let in_flight = self.send_op.is_some();
            drain_tls(tls, &mut self.wire, &mut self.deferred, in_flight)?;
        }
        if rest.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::Tls(String::from("TLS write made no progress")))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.inflight == 0 {
            if self.close_op.is_none() {
                close_raw(self.fd);
            }
            return;
        }
        // A staged or submitted operation keeps the raw pointers and descriptor
        // it was prepared with until its final CQE, and `Drop` has no proactor to
        // cancel it. Freeing those operands would be a use-after-free, and
        // closing the descriptor would let a later submission target a recycled
        // file, so exactly the referenced allocations are leaked.
        std::mem::forget(std::mem::replace(&mut self.rx, Box::new([])));
        std::mem::forget(std::mem::take(&mut self.wire));
        std::mem::forget(self.peer.take());
        std::mem::forget(self.timer.take());
    }
}
