//! Session protocol state and retained descriptor, buffer, and TLS ownership.

use super::*;

/// Shared guards for session establishment, delivery and terminal drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SessionSuperstate {
    Connecting,
    Open,
    Closing,
    Closed,
}

/// Close notification and cancellation are substates, so a callback cannot
/// reopen application delivery while a close reply still owns wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SessionPhase {
    Resolving,
    Connecting,
    Handshaking,
    Upgrading,
    Open,
    CloseFlush,
    CloseNotified,
    Teardown,
    TeardownNotified,
    Closed,
}
impl SessionPhase {
    pub(super) const fn superstate(self) -> SessionSuperstate {
        match self {
            Self::Resolving | Self::Connecting | Self::Handshaking | Self::Upgrading => {
                SessionSuperstate::Connecting
            }
            Self::Open => SessionSuperstate::Open,
            Self::Closed => SessionSuperstate::Closed,
            Self::CloseFlush | Self::CloseNotified | Self::Teardown | Self::TeardownNotified => {
                SessionSuperstate::Closing
            }
        }
    }
    pub(super) const fn is_closing(self) -> bool {
        matches!(
            self.superstate(),
            SessionSuperstate::Closing | SessionSuperstate::Closed
        )
    }
    pub(super) const fn is_teardown(self) -> bool {
        matches!(self, Self::Teardown | Self::TeardownNotified | Self::Closed)
    }
    pub(super) fn begin_teardown(&mut self) {
        *self = if matches!(self, Self::CloseNotified | Self::TeardownNotified) {
            Self::TeardownNotified
        } else {
            Self::Teardown
        };
    }
    pub(super) fn notify_close(&mut self) -> bool {
        if matches!(
            self,
            Self::CloseNotified | Self::TeardownNotified | Self::Closed
        ) {
            return false;
        }
        *self = if self.is_teardown() {
            Self::TeardownNotified
        } else {
            Self::CloseNotified
        };
        true
    }
}

/// One completed family query: lookup ticket, addresses, failure text.
pub(super) type DnsOutcome = (u64, Vec<SocketAddr>, Option<String>);

/// Owned state of one connection attempt or established WebSocket.
pub(super) struct Session {
    pub(super) id: WebSocketSessionId,
    pub(super) uri: Uri,
    pub(super) phase: SessionPhase,
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
            phase: SessionPhase::Resolving,
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
