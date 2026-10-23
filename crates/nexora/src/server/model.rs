//! Accepted-connection state owned by the listening server.

use std::{cell::Cell, net::SocketAddr, os::fd::RawFd, rc::Rc};

use liburing::Completion;

use super::{
    MAX_CONN,
    config::ServerConfig,
    net::{blank_addr, conn_mut},
};
use crate::{
    IoUringSocket, SubsystemInbox, WebSocketSessionId,
    proto::{BytesMut, Http1ServerCodec, Http2Connection, WebSocketCodec},
    websocket_server::WebSocketUpgradeHandler,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Sniff,
    Http1,
    Http2,
    WebSocket,
    Dead,
}

pub(super) struct Conn {
    pub(super) id: u64,
    pub(super) sock: IoUringSocket,
    pub(super) mode: Mode,
    pub(super) raw: BytesMut,
    pub(super) plain: BytesMut,
    pub(super) pending: BytesMut,
    pub(super) inflight_tx: usize,
    pub(super) recv_on: bool,
    pub(super) send_on: bool,
    pub(super) close_on: bool,
    pub(super) close_pending: bool,
    pub(super) http_close: bool,
    pub(super) outstanding: u32,
    pub(super) http1: Http1ServerCodec,
    pub(super) http2: Option<Http2Connection>,
    pub(super) websocket: Option<WebSocketCodec>,
    pub(super) websocket_id: Option<WebSocketSessionId>,
    pub(super) gates: Vec<(Option<u32>, Rc<Cell<bool>>)>,
}

pub(super) struct State<S> {
    pub(super) config: ServerConfig,
    pub(super) service: S,
    pub(super) inbox: SubsystemInbox,
    pub(super) local: SocketAddr,
    pub(super) listener: Option<RawFd>,
    pub(super) accept_addr: libc::sockaddr_storage,
    pub(super) accept_len: libc::socklen_t,
    pub(super) accept_on: bool,
    pub(super) shutting_down: bool,
    pub(super) next_id: u64,
    pub(super) conns: Vec<Option<Conn>>,
    pub(super) completions: Vec<Completion>,
    pub(super) websocket_path: String,
    pub(super) websocket: Option<Box<dyn WebSocketUpgradeHandler>>,
}

impl<S> State<S> {
    pub(super) fn new(config: ServerConfig, service: S, fd: RawFd, local: SocketAddr) -> Self {
        Self {
            config,
            service,
            inbox: SubsystemInbox::new(),
            local,
            listener: Some(fd),
            accept_addr: blank_addr(),
            accept_len: 0,
            accept_on: false,
            shutting_down: false,
            next_id: 1,
            conns: Vec::new(),
            completions: Vec::new(),
            websocket_path: String::new(),
            websocket: None,
        }
    }

    pub(super) fn busy(&self) -> bool {
        self.accept_on
            || self.conns.iter().any(|slot| {
                slot.as_ref()
                    .is_some_and(|conn| conn.recv_on || conn.send_on || conn.close_on)
            })
    }

    pub(super) fn live_count(&self) -> usize {
        self.conns.iter().filter(|slot| slot.is_some()).count()
    }

    pub(super) fn insert_conn(&mut self, conn: Conn) -> bool {
        if let Some(slot) = self.conns.iter().position(|item| item.is_none()) {
            self.conns[slot] = Some(conn);
            return true;
        }
        if self.conns.len() >= MAX_CONN {
            return false;
        }
        self.conns.push(Some(conn));
        true
    }

    pub(super) fn note_quiescent(&mut self, slot: usize) {
        let shutdown = self.shutting_down;
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return;
        };
        let idle =
            conn.outstanding == 0 && conn.pending.is_empty() && !conn.send_on && !conn.recv_on;
        if idle && (conn.http_close || shutdown) {
            conn.close_pending = true;
        }
    }

    pub(super) fn finish_stream(&mut self, slot: usize, stream: Option<u32>) {
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return;
        };
        let mut removed = 0u32;
        conn.gates.retain(|(id, gate)| {
            if *id == stream {
                gate.set(false);
                removed = removed.saturating_add(1);
                false
            } else {
                true
            }
        });
        conn.outstanding = conn.outstanding.saturating_sub(removed);
    }

    pub(super) fn fail_all_gates(&mut self, slot: usize) {
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return;
        };
        for (_, gate) in &conn.gates {
            gate.set(false);
        }
        conn.gates.clear();
        conn.outstanding = 0;
    }

    pub(super) fn fail_conn(&mut self, slot: usize) {
        self.fail_all_gates(slot);
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.mode = Mode::Dead;
            conn.http_close = true;
            conn.close_pending = conn.pending.is_empty() && !conn.send_on && !conn.recv_on;
        }
    }

    pub(super) fn slot_of_id(&self, id: u64) -> Option<usize> {
        self.conns
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|conn| conn.id == id))
    }

    pub(super) fn slot_of_websocket(&self, id: WebSocketSessionId) -> Option<usize> {
        self.conns.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|conn| conn.websocket_id == Some(id))
        })
    }
}

impl<S> Drop for State<S> {
    fn drop(&mut self) {
        if self.accept_on {
            return;
        }
        if let Some(fd) = self.listener.take() {
            // SAFETY: accept is not in flight, so this state is the only owner
            // of the listening descriptor.
            unsafe { libc::close(fd) };
        }
    }
}
