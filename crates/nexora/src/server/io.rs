//! Accept, receive, send, and close submissions for accepted sockets.

use liburing::{
    Completion, Proactor,
    ops::net::{prep_accept, prep_close, prep_recv, prep_send},
};

use super::{
    KIND_ACCEPT, KIND_CLOSE, KIND_RECV, KIND_SEND, MAX_CONN,
    model::{Conn, Mode, State},
    net::{conn_mut, pack, sockaddr_to_std, unpack, want_recv},
    service::HttpService,
};
use crate::{
    Error, IoUringSocket, Result, SocketState,
    proto::{BytesMut, Http1ServerCodec, Http1ServerConfig},
};

impl<S: HttpService> State<S> {
    pub(super) fn apply_completions(&mut self) -> Result<usize> {
        let batch = std::mem::take(&mut self.completions);
        let count = batch.len();
        let mut first_error = None;
        for completion in batch {
            if let Err(error) = self.on_completion(completion)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(count),
        }
    }

    pub(super) fn on_completion(&mut self, completion: Completion) -> Result<()> {
        let (kind, slot) = unpack(completion.operation_id);
        let slot = usize::try_from(slot).unwrap_or(usize::MAX);
        match kind {
            KIND_ACCEPT => self.on_accept(completion.result),
            KIND_RECV => self.on_recv(slot, completion.result),
            KIND_SEND => self.on_send(slot, completion.result),
            KIND_CLOSE => self.on_close(slot),
            _ => Ok(()),
        }
    }

    pub(super) fn on_accept(&mut self, result: i32) -> Result<()> {
        self.accept_on = false;
        if result < 0 {
            if matches!(
                result.saturating_neg(),
                libc::EAGAIN | libc::EINTR | libc::ECONNABORTED
            ) {
                return Ok(());
            }
            return Err(Error::Io(std::io::Error::from_raw_os_error(
                result.saturating_neg(),
            )));
        }
        let fd = result;
        if self.shutting_down || self.live_count() >= MAX_CONN {
            // SAFETY: the accept completion transferred this descriptor to us,
            // and it is not installed in a connection yet.
            unsafe { libc::close(fd) };
            return Ok(());
        }
        let peer = match sockaddr_to_std(&self.accept_addr, self.accept_len) {
            Ok(peer) => peer,
            Err(error) => {
                // SAFETY: accept transferred this descriptor, and it is not
                // installed in a connection yet.
                unsafe { libc::close(fd) };
                return Err(error);
            }
        };
        let mut sock =
            match IoUringSocket::new(fd, self.config.io_buffer_size, self.config.io_buffer_size) {
                Ok(sock) => sock,
                Err(error) => {
                    // SAFETY: `IoUringSocket::new` leaves `fd` owned by the caller on failure.
                    unsafe { libc::close(fd) };
                    return Err(error);
                }
            };
        sock.begin_connect()?;
        let close_now = sock.connect_completed(true)?;
        if close_now {
            return Ok(());
        }
        sock.set_peer_addr(peer);
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let conn = Conn {
            id,
            sock,
            mode: Mode::Sniff,
            raw: BytesMut::new(),
            plain: BytesMut::new(),
            pending: BytesMut::new(),
            inflight_tx: 0,
            recv_on: false,
            send_on: false,
            close_on: false,
            close_pending: false,
            http_close: false,
            outstanding: 0,
            http1: Http1ServerCodec::new(Http1ServerConfig {
                max_header_list_size: self.config.max_header_list_size,
                max_body_size: self.config.max_body_size,
            }),
            http2: None,
            websocket: None,
            websocket_id: None,
            gates: Vec::new(),
        };
        if !self.insert_conn(conn) {
            return Ok(());
        }
        Ok(())
    }

    pub(super) fn on_recv(&mut self, slot: usize, result: i32) -> Result<()> {
        let mut retire_failed = false;
        let present = if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.recv_on = false;
            match conn.sock.complete_op() {
                Ok(true) => conn.close_pending = true,
                Ok(false) => {}
                Err(_) => retire_failed = true,
            }
            true
        } else {
            false
        };
        if !present || retire_failed || result <= 0 {
            if present {
                self.fail_conn(slot);
            }
            return Ok(());
        }
        let n = usize::try_from(result).unwrap_or(0);
        let copied = match conn_mut(&mut self.conns, slot) {
            None => return Ok(()),
            Some(conn) => match conn.sock.rx_buffer() {
                Some(buf) if n <= buf.len() => Some(buf[..n].to_vec()),
                _ => None,
            },
        };
        let Some(copied) = copied else {
            self.fail_conn(slot);
            return Ok(());
        };
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.raw.extend_from_slice(&copied);
            if conn.mode == Mode::Dead {
                return Ok(());
            }
        }
        self.pump_slot(slot)
    }

    pub(super) fn on_send(&mut self, slot: usize, result: i32) -> Result<()> {
        let mut retire_failed = false;
        let present = if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.send_on = false;
            match conn.sock.complete_op() {
                Ok(true) => conn.close_pending = true,
                Ok(false) => {}
                Err(_) => retire_failed = true,
            }
            true
        } else {
            false
        };
        if !present || retire_failed || result < 0 {
            if present {
                self.fail_conn(slot);
            }
            return Ok(());
        }
        let n = usize::try_from(result).unwrap_or(0);
        if let Some(conn) = conn_mut(&mut self.conns, slot) {
            let advance = n.min(conn.inflight_tx).min(conn.pending.len());
            conn.pending.advance(advance);
            conn.inflight_tx = 0;
        }
        self.pump_slot(slot)
    }

    pub(super) fn on_close(&mut self, slot: usize) -> Result<()> {
        let failed = if let Some(conn) = conn_mut(&mut self.conns, slot) {
            conn.close_on = false;
            conn.sock.close_completed().is_err()
        } else {
            false
        };
        if failed {
            self.fail_all_gates(slot);
        }
        if slot < self.conns.len() {
            self.conns[slot] = None;
        }
        Ok(())
    }

    pub(super) fn arm(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.arm_accept(proactor)?;
        let slots: Vec<usize> = (0..self.conns.len()).collect();
        for slot in slots {
            self.note_quiescent(slot);
            self.arm_send(proactor, slot)?;
            self.arm_recv(proactor, slot)?;
            self.arm_close(proactor, slot)?;
        }
        Ok(())
    }

    pub(super) fn arm_accept(&mut self, proactor: &mut Proactor) -> Result<()> {
        if self.accept_on || self.shutting_down {
            return Ok(());
        }
        let Some(fd) = self.listener else {
            return Ok(());
        };
        self.accept_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let addr = std::ptr::addr_of_mut!(self.accept_addr).cast::<libc::sockaddr>();
        let len_ptr = std::ptr::addr_of_mut!(self.accept_len);
        let op = pack(self.config.net_subsystem, KIND_ACCEPT, 0);
        proactor
            .prepare_sqe_with(op, |sqe| {
                // SAFETY: `sqe` is exclusive to this callback. `addr` and `len_ptr`
                // point into this `Rc`-owned state, which is not moved, and `fd`
                // stays open while `accept_on` is set.
                unsafe {
                    prep_accept(
                        sqe,
                        fd,
                        addr,
                        len_ptr,
                        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    );
                }
            })
            .map_err(Error::from)?;
        self.accept_on = true;
        Ok(())
    }

    pub(super) fn arm_send(&mut self, proactor: &mut Proactor, slot: usize) -> Result<()> {
        let subsystem = self.config.net_subsystem;
        let Ok(slot_u) = u32::try_from(slot) else {
            return Err(Error::InvalidState(String::from("slot overflow")));
        };
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Ok(());
        };
        if conn.send_on || conn.pending.is_empty() || conn.sock.state() != SocketState::Connected {
            return Ok(());
        }
        let n = {
            let src = conn.pending.as_ref();
            let Some(dst) = conn.sock.tx_buffer_mut() else {
                return Ok(());
            };
            let n = src.len().min(dst.len());
            if n == 0 {
                return Ok(());
            }
            dst[..n].copy_from_slice(&src[..n]);
            n
        };
        conn.sock.begin_op()?;
        let Some(fd) = conn.sock.fd() else {
            let close_now = conn.sock.complete_op()?;
            if close_now {
                conn.close_pending = true;
            }
            return Err(Error::ConnectionClosed);
        };
        let Some(ptr) = conn.sock.tx_buffer_mut().map(|buf| buf.as_mut_ptr()) else {
            let close_now = conn.sock.complete_op()?;
            if close_now {
                conn.close_pending = true;
            }
            return Err(Error::InvalidState(String::from(
                "transmit buffer released",
            )));
        };
        if let Err(error) = proactor.prepare_sqe_with(pack(subsystem, KIND_SEND, slot_u), |sqe| {
            // SAFETY: `sqe` is exclusive to this callback. `ptr` addresses the
            // socket transmit buffer, which stays allocated until close completion,
            // and `fd` stays open until that close.
            unsafe { prep_send(sqe, fd, ptr, n, 0) }
        }) {
            let close_now = conn.sock.complete_op()?;
            if close_now {
                conn.close_pending = true;
            }
            return Err(Error::from(error));
        }
        conn.send_on = true;
        conn.inflight_tx = n;
        Ok(())
    }

    pub(super) fn arm_recv(&mut self, proactor: &mut Proactor, slot: usize) -> Result<()> {
        let shutdown = self.shutting_down;
        let subsystem = self.config.net_subsystem;
        let Ok(slot_u) = u32::try_from(slot) else {
            return Err(Error::InvalidState(String::from("slot overflow")));
        };
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Ok(());
        };
        if !want_recv(conn, shutdown) {
            return Ok(());
        }
        conn.sock.begin_op()?;
        let Some(fd) = conn.sock.fd() else {
            let close_now = conn.sock.complete_op()?;
            if close_now {
                conn.close_pending = true;
            }
            return Err(Error::ConnectionClosed);
        };
        let Some((ptr, len)) = conn
            .sock
            .rx_buffer_mut()
            .map(|buf| (buf.as_mut_ptr(), buf.len()))
        else {
            let close_now = conn.sock.complete_op()?;
            if close_now {
                conn.close_pending = true;
            }
            return Err(Error::InvalidState(String::from("receive buffer released")));
        };
        if let Err(error) = proactor.prepare_sqe_with(pack(subsystem, KIND_RECV, slot_u), |sqe| {
            // SAFETY: `sqe` is exclusive to this callback. `ptr` addresses the
            // socket receive buffer, which stays allocated until close completion,
            // and `fd` stays open until that close.
            unsafe { prep_recv(sqe, fd, ptr, len, 0) }
        }) {
            let close_now = conn.sock.complete_op()?;
            if close_now {
                conn.close_pending = true;
            }
            return Err(Error::from(error));
        }
        conn.recv_on = true;
        Ok(())
    }

    pub(super) fn arm_close(&mut self, proactor: &mut Proactor, slot: usize) -> Result<()> {
        let subsystem = self.config.net_subsystem;
        let Ok(slot_u) = u32::try_from(slot) else {
            return Err(Error::InvalidState(String::from("slot overflow")));
        };
        let closed = {
            let Some(conn) = conn_mut(&mut self.conns, slot) else {
                return Ok(());
            };
            if conn.close_on
                || !conn.close_pending
                || conn.send_on
                || conn.recv_on
                || !conn.pending.is_empty()
            {
                return Ok(());
            }
            conn.sock.state() == SocketState::Closed
        };
        if closed {
            self.conns[slot] = None;
            return Ok(());
        }
        let Some(conn) = conn_mut(&mut self.conns, slot) else {
            return Ok(());
        };
        if !conn.sock.request_close() {
            return Ok(());
        }
        let Some(fd) = conn.sock.fd() else {
            return Ok(());
        };
        if let Err(error) = proactor.prepare_sqe_with(pack(subsystem, KIND_CLOSE, slot_u), |sqe| {
            // SAFETY: `sqe` is exclusive to this callback. `fd` stays owned by the
            // socket until `close_started` records the staged close.
            unsafe { prep_close(sqe, fd) }
        }) {
            conn.sock.close_submission_failed()?;
            return Err(Error::from(error));
        }
        conn.sock.close_started()?;
        conn.close_on = true;
        Ok(())
    }
}
