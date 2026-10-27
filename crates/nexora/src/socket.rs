//! Socket descriptor, pinned-buffer, and cancellation state for the proactor driver.
//!
//! [`IoUringSocket`] owns one non-blocking descriptor and the fixed-address
//! receive and transmit buffers referenced by `io_uring` operations; a connect,
//! receive, or send keeps both alive until its own final completion.
//!
//! A cancel completion proves nothing about the target, which may still write
//! its buffers: operations are quarantined in [`SocketState::Cancelling`] until
//! the last retire, and storage is released only by
//! [`IoUringSocket::close_completed`].

use std::{net::SocketAddr, os::fd::RawFd};

use crate::{
    error::{Error, Result},
    proto::TlsSession,
};

/// Largest buffer capacity that `Vec` accepts instead of reporting a capacity
/// overflow.
const MAX_BUFFER_CAPACITY: usize = isize::MAX as usize;

/// Lifecycle state of an [`IoUringSocket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// No connect has been started and no operation is in flight.
    Idle,
    /// A CONNECT operation is in flight.
    Connecting,
    /// The connection is established; receive and send operations may start.
    Connected,
    /// Cancellation was requested and in-flight operations must still finish.
    Cancelling,
    /// No operation is in flight and the socket is waiting for its close
    /// submission or completion.
    Closing,
    /// The close completion was observed; descriptor and buffers are gone.
    Closed,
}

/// Shared admission guards for socket phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketSuperstate {
    Inactive,
    Establishing,
    Active,
    Teardown,
}

/// Descriptor ownership and close-submission substates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketPhase {
    Idle,
    Connecting,
    Connected,
    Cancelling,
    CancelRequested,
    CloseReady,
    CloseQueued,
    CloseSubmitted,
    Closed,
}
impl SocketPhase {
    /// Returns the parent whose admission and retirement rules apply.
    pub const fn superstate(self) -> SocketSuperstate {
        match self {
            Self::Idle | Self::Closed => SocketSuperstate::Inactive,
            Self::Connecting => SocketSuperstate::Establishing,
            Self::Connected => SocketSuperstate::Active,
            Self::Cancelling
            | Self::CancelRequested
            | Self::CloseReady
            | Self::CloseQueued
            | Self::CloseSubmitted => SocketSuperstate::Teardown,
        }
    }
}

/// Owns one non-blocking socket, its optional TLS session, and the
/// fixed-address receive and transmit buffers used by `io_uring` operations.
///
/// A cancellation or close requested while operations are in flight is
/// deferred through [`SocketState::Cancelling`] until the last operation
/// completes, so a descriptor is never closed and a buffer is never freed
/// while a submitted operation can still reference them. Buffers move only in
/// [`IoUringSocket::renew_buffers`] while no operation is in flight, and are
/// released only by [`IoUringSocket::close_completed`] or by a drop that
/// abandons them.
pub struct IoUringSocket {
    fd: Option<RawFd>,
    phase: SocketPhase,
    tls: Option<TlsSession>,
    rx_buffer: Option<Box<[u8]>>,
    tx_buffer: Option<Box<[u8]>>,
    in_flight_ops: usize,
    peer: Option<SocketAddr>,
}

impl IoUringSocket {
    /// Creates a socket wrapper around `fd` with zeroed receive and transmit
    /// buffers, switching the descriptor to non-blocking mode if needed.
    /// Ownership of `fd` transfers only on success.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] for a zero or unallocatable capacity and
    /// [`Error::Io`] when reading or updating the status flags fails.
    ///
    /// # Panics
    /// This function does not panic; an unsatisfiable allocation aborts the process.
    pub fn new(fd: RawFd, rx_capacity: usize, tx_capacity: usize) -> Result<Self> {
        validate_capacities(rx_capacity, tx_capacity)?;
        let flags = fcntl_status(fd, libc::F_GETFL, 0)?;
        if flags & libc::O_NONBLOCK == 0 {
            let _updated = fcntl_status(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)?;
        }

        // Allocate both before assignment, so a failed allocation changes nothing.
        let rx_buffer = zeroed_buffer(rx_capacity);
        let tx_buffer = zeroed_buffer(tx_capacity);
        Ok(Self {
            fd: Some(fd),
            phase: SocketPhase::Idle,
            tls: None,
            rx_buffer: Some(rx_buffer),
            tx_buffer: Some(tx_buffer),
            in_flight_ops: 0,
            peer: None,
        })
    }

    /// Returns the descriptor while the socket owns it; `None` once the close
    /// SQE was recorded, because the close operation owns it from submission.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn fd(&self) -> Option<RawFd> {
        if self.close_submitted() {
            None
        } else {
            self.fd
        }
    }

    /// Returns the current lifecycle state.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn state(&self) -> SocketState {
        match self.phase {
            SocketPhase::Idle => SocketState::Idle,
            SocketPhase::Connecting => SocketState::Connecting,
            SocketPhase::Connected => SocketState::Connected,
            SocketPhase::Cancelling | SocketPhase::CancelRequested => SocketState::Cancelling,
            SocketPhase::CloseReady | SocketPhase::CloseQueued | SocketPhase::CloseSubmitted => {
                SocketState::Closing
            }
            SocketPhase::Closed => SocketState::Closed,
        }
    }

    /// Returns the descriptor-ownership phase, including close submission.
    pub const fn phase(&self) -> SocketPhase {
        self.phase
    }

    const fn close_requested(&self) -> bool {
        matches!(
            self.phase,
            SocketPhase::CancelRequested
                | SocketPhase::CloseQueued
                | SocketPhase::CloseSubmitted
                | SocketPhase::Closed
        )
    }

    /// Returns the TLS session associated with the socket, if any.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn tls(&self) -> Option<&TlsSession> {
        self.tls.as_ref()
    }

    /// Returns the TLS session for mutation by the protocol driver.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn tls_mut(&mut self) -> Option<&mut TlsSession> {
        self.tls.as_mut()
    }

    /// Installs `tls`, dropping any previously installed session.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_tls(&mut self, tls: TlsSession) {
        self.tls = Some(tls);
    }

    /// Removes and returns the TLS session, if one is installed.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn take_tls(&mut self) -> Option<TlsSession> {
        self.tls.take()
    }

    /// Reports whether a TLS session is installed.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Returns the peer address recorded for the connection, if any.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Records the peer address reported by a completed CONNECT or ACCEPT.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_peer_addr(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    /// Returns the receive buffer, or `None` once it has been released.
    ///
    /// While a receive is in flight the bytes are owned by the kernel; reading
    /// them before the final CQE can observe a partial write.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn rx_buffer(&self) -> Option<&[u8]> {
        self.rx_buffer.as_deref()
    }

    /// Returns the writable receive buffer for a receive submission.
    ///
    /// The slice keeps its address until [`Self::renew_buffers`] succeeds.
    /// While a receive is in flight the kernel owns it exclusively: do not read
    /// or write it until the final CQE.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn rx_buffer_mut(&mut self) -> Option<&mut [u8]> {
        self.rx_buffer.as_deref_mut()
    }

    /// Returns the transmit buffer, or `None` once it has been released.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn tx_buffer(&self) -> Option<&[u8]> {
        self.tx_buffer.as_deref()
    }

    /// Returns the writable transmit buffer for a send submission.
    ///
    /// The slice keeps its address until [`Self::renew_buffers`] succeeds. Do
    /// not modify the bytes until the send's final CQE.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn tx_buffer_mut(&mut self) -> Option<&mut [u8]> {
        self.tx_buffer.as_deref_mut()
    }

    /// Returns the number of submitted operations whose final CQE has not
    /// arrived.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn in_flight_ops(&self) -> usize {
        self.in_flight_ops
    }

    /// Reports whether the close completion has been observed.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn is_closed(&self) -> bool {
        matches!(self.state(), SocketState::Closed)
    }

    /// Reports whether the close SQE has been recorded as submitted.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn close_submitted(&self) -> bool {
        matches!(
            self.phase,
            SocketPhase::CloseSubmitted | SocketPhase::Closed
        )
    }

    /// Replaces both buffers with newly allocated zeroed storage.
    ///
    /// Renewal is refused while the kernel can still reference the old
    /// allocations: an in-flight operation, an outstanding close request, or
    /// the closing/closed state blocks it. Both allocations happen before
    /// either field changes, so a rejected call changes nothing.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] for a pending close, an in-flight
    /// operation, or a zero or unallocatable capacity.
    ///
    /// # Panics
    /// This function does not panic; an unsatisfiable allocation aborts the process.
    pub fn renew_buffers(&mut self, rx_capacity: usize, tx_capacity: usize) -> Result<()> {
        if matches!(self.state(), SocketState::Closing | SocketState::Closed) {
            return Err(Error::InvalidState(
                "cannot renew buffers while the socket is closing or closed".to_owned(),
            ));
        }
        if self.close_requested() || self.close_submitted() {
            return Err(Error::InvalidState(
                "cannot renew buffers after a close was requested".to_owned(),
            ));
        }
        if self.in_flight_ops != 0 {
            return Err(Error::InvalidState(format!(
                "cannot renew buffers while {} operations are in flight",
                self.in_flight_ops
            )));
        }
        validate_capacities(rx_capacity, tx_capacity)?;

        // The replacements exist before the old allocations drop, so their
        // addresses never alias the storage the kernel used.
        let rx_buffer = zeroed_buffer(rx_capacity);
        let tx_buffer = zeroed_buffer(tx_capacity);
        self.rx_buffer = Some(rx_buffer);
        self.tx_buffer = Some(tx_buffer);
        Ok(())
    }

    /// Marks the start of a non-blocking CONNECT on an idle socket. The connect
    /// counts as an in-flight operation, so quarantine covers it before its
    /// completion arrives; report it with [`Self::connect_completed`], never
    /// with [`Self::complete_op`].
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] unless the socket is idle.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn begin_connect(&mut self) -> Result<()> {
        if !matches!(self.state(), SocketState::Idle) {
            return Err(Error::InvalidState(format!(
                "connect requires an idle socket, current state is {:?}",
                self.state()
            )));
        }

        self.start_op()?;
        self.phase = SocketPhase::Connecting;
        Ok(())
    }

    /// Reports the final CQE of a CONNECT operation.
    ///
    /// `Ok(true)` tells the caller to submit the close now. A successful
    /// connect moves to [`SocketState::Connected`] and a failed one to
    /// [`SocketState::Closing`]; under [`SocketState::Cancelling`] the
    /// completion only retires the operation, so cancellation wins.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] unless the socket is connecting or
    /// cancelling, or when no operation is in flight.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn connect_completed(&mut self, success: bool) -> Result<bool> {
        match self.state() {
            SocketState::Connecting => {
                // `retire_op` cannot report a last-operation transition here:
                // only `Cancelling` converts a retirement into `Closing`.
                self.retire_op("CONNECT")?;
                if success {
                    self.phase = SocketPhase::Connected;
                    Ok(false)
                } else {
                    self.phase = SocketPhase::CloseReady;
                    Ok(true)
                }
            }
            SocketState::Cancelling => self.retire_op("CONNECT"),
            _ => Err(Error::InvalidState(format!(
                "connect completion requires the connecting or cancelling state, current state is \
                 {:?}",
                self.state()
            ))),
        }
    }

    /// Marks the start of a receive or send operation on a connected socket.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] unless the socket is connected.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn begin_op(&mut self) -> Result<()> {
        if !matches!(self.state(), SocketState::Connected) {
            return Err(Error::InvalidState(format!(
                "receive or send requires a connected socket, current state is {:?}",
                self.state()
            )));
        }

        self.start_op()
    }

    /// Reports the final CQE of a receive or send operation.
    ///
    /// `Ok(true)` tells the caller to submit the close now. Call it exactly
    /// once per submitted operation; a cancel completion is not reported here
    /// because the target CQE still owns its in-flight count.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] when the socket is not connected or
    /// cancelling, or when no operation is in flight. Rejecting an empty count
    /// keeps the close path from freeing buffers the kernel can still write.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn complete_op(&mut self) -> Result<bool> {
        if !matches!(
            self.state(),
            SocketState::Connected | SocketState::Cancelling
        ) {
            return Err(Error::InvalidState(format!(
                "receive or send completion requires the connected or cancelling state, current \
                 state is {:?}",
                self.state()
            )));
        }
        self.retire_op("receive or send")
    }

    /// Requests cancellation of every in-flight operation without releasing
    /// any storage.
    ///
    /// Returns `true` when the caller must submit the close now. With
    /// operations in flight the socket moves to [`SocketState::Cancelling`] and
    /// this returns `false`; each completion then drives it towards `Closing`.
    /// A socket that is already cancelling, closing, or closed is unchanged.
    #[must_use]
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn request_cancel(&mut self) -> bool {
        match self.state() {
            SocketState::Idle | SocketState::Connecting | SocketState::Connected => {
                if self.in_flight_ops > 0 {
                    self.phase = SocketPhase::Cancelling;
                    false
                } else {
                    self.phase = SocketPhase::CloseReady;
                    true
                }
            }
            SocketState::Cancelling | SocketState::Closing | SocketState::Closed => false,
        }
    }

    /// Requests connection shutdown after every in-flight operation finishes.
    ///
    /// Returns `true` only for the first caller that may submit the close; with
    /// operations in flight the socket moves to [`SocketState::Cancelling`] and
    /// the completion that retires the last operation then returns `true`.
    #[must_use]
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn request_close(&mut self) -> bool {
        if self.is_closed() || self.close_requested() {
            return false;
        }
        if self.in_flight_ops > 0 {
            self.phase = SocketPhase::CancelRequested;
            false
        } else {
            self.phase = SocketPhase::CloseQueued;
            true
        }
    }

    /// Records that the close SQE was staged for the descriptor.
    ///
    /// Call it after staging succeeds; two closes on one descriptor would make
    /// the second act on a reused descriptor number.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] for a recorded close, an in-flight
    /// operation, or a state other than closing.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn close_started(&mut self) -> Result<()> {
        if !matches!(self.state(), SocketState::Closing) {
            return Err(Error::InvalidState(format!(
                "close submission requires the closing state, current state is {:?}",
                self.state()
            )));
        }
        if self.close_submitted() {
            return Err(Error::InvalidState(
                "close was already submitted for this socket".to_owned(),
            ));
        }
        if self.in_flight_ops != 0 {
            return Err(Error::InvalidState(format!(
                "close submission requires an idle kernel, {} operations are in flight",
                self.in_flight_ops
            )));
        }

        self.phase = SocketPhase::CloseSubmitted;
        Ok(())
    }

    /// Releases a close request whose SQE could not be staged.
    ///
    /// The socket stays in [`SocketState::Closing`] and [`Self::request_close`]
    /// may return `true` again.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] when the close SQE was recorded as
    /// submitted; retrying then could close the descriptor twice.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn close_submission_failed(&mut self) -> Result<()> {
        if self.close_submitted() {
            return Err(Error::InvalidState(
                "close SQE was already recorded as submitted; a retry would close twice".to_owned(),
            ));
        }
        self.phase = match self.phase {
            SocketPhase::CancelRequested => SocketPhase::Cancelling,
            SocketPhase::CloseQueued => SocketPhase::CloseReady,
            phase @ (SocketPhase::Idle
            | SocketPhase::Connecting
            | SocketPhase::Connected
            | SocketPhase::Cancelling
            | SocketPhase::CloseReady
            | SocketPhase::CloseSubmitted
            | SocketPhase::Closed) => phase,
        };
        Ok(())
    }

    /// Reports the final close CQE and releases the descriptor value and both
    /// buffers.
    ///
    /// The kernel close already released the descriptor, so the raw value is
    /// dropped without another `close` syscall. Buffers are freed here and
    /// nowhere earlier: every submitted operation already delivered its final
    /// completion.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] unless the socket is closing, the close
    /// was recorded by [`Self::close_started`], and no operation is in flight.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn close_completed(&mut self) -> Result<()> {
        if !matches!(self.state(), SocketState::Closing) {
            return Err(Error::InvalidState(format!(
                "close completion requires the closing state, current state is {:?}",
                self.state()
            )));
        }
        if !self.close_submitted() {
            return Err(Error::InvalidState(
                "close completion arrived before the close was submitted".to_owned(),
            ));
        }
        if self.in_flight_ops != 0 {
            return Err(Error::InvalidState(format!(
                "close completion arrived while {} operations are still in flight",
                self.in_flight_ops
            )));
        }

        self.phase = SocketPhase::Closed;
        self.rx_buffer = None;
        self.tx_buffer = None;
        // The kernel close already released the descriptor; dropping the raw
        // value must not close it a second time.
        self.fd = None;
        Ok(())
    }

    fn start_op(&mut self) -> Result<()> {
        self.in_flight_ops = self.in_flight_ops.checked_add(1).ok_or_else(|| {
            Error::InvalidState("in-flight operation count overflowed".to_owned())
        })?;
        Ok(())
    }

    /// Retires one operation and reports whether the caller must submit the
    /// close now.
    fn retire_op(&mut self, operation: &str) -> Result<bool> {
        self.in_flight_ops = self.in_flight_ops.checked_sub(1).ok_or_else(|| {
            Error::InvalidState(format!(
                "{operation} completion arrived with no operation in flight"
            ))
        })?;
        if self.in_flight_ops == 0 && matches!(self.state(), SocketState::Cancelling) {
            self.phase = if self.close_requested() {
                SocketPhase::CloseQueued
            } else {
                SocketPhase::CloseReady
            };
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Abandons both pinned allocations without freeing them.
    fn forget_buffers(&mut self) {
        if let Some(rx) = self.rx_buffer.take() {
            std::mem::forget(rx);
        }
        if let Some(tx) = self.tx_buffer.take() {
            std::mem::forget(tx);
        }
    }
}

impl Drop for IoUringSocket {
    fn drop(&mut self) {
        if self.close_submitted() {
            // The staged close operation owns the descriptor and will close it.
            // No other operation is in flight, but the buffers are abandoned
            // rather than freed so a future accounting change cannot turn this
            // drop into a use-after-free.
            self.forget_buffers();
            self.fd = None;
            return;
        }
        if self.in_flight_ops > 0 {
            // The kernel can still write the buffers, so they are abandoned.
            self.forget_buffers();
        }
        if let Some(fd) = self.fd.take() {
            // SAFETY: no close SQE was submitted, so this socket is the sole
            // owner of the descriptor and closes it exactly once. Each pending
            // operation holds its own kernel file reference, which closing the
            // descriptor table entry does not invalidate.
            unsafe {
                libc::close(fd);
            }
        }
    }
}

fn validate_capacities(rx_capacity: usize, tx_capacity: usize) -> Result<()> {
    if rx_capacity == 0 || tx_capacity == 0 {
        return Err(Error::InvalidState(
            "socket buffers must have nonzero capacity".to_owned(),
        ));
    }
    let capacity = rx_capacity.max(tx_capacity);
    if capacity > MAX_BUFFER_CAPACITY {
        return Err(Error::InvalidState(format!(
            "socket buffer capacity {capacity} exceeds the maximum allocation size"
        )));
    }
    Ok(())
}

fn zeroed_buffer(capacity: usize) -> Box<[u8]> {
    vec![0u8; capacity].into_boxed_slice()
}

/// Runs one descriptor status call, retrying after `EINTR`.
///
/// # Errors
/// Returns [`Error::Io`] for any failure other than interruption.
fn fcntl_status(fd: RawFd, command: libc::c_int, argument: libc::c_int) -> Result<libc::c_int> {
    loop {
        // SAFETY: the caller owns `fd` and supplies the argument the command
        // expects; only that descriptor's status flags are read or written.
        let result = unsafe { libc::fcntl(fd, command, argument) };
        if result >= 0 {
            return Ok(result);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(Error::Io(error));
        }
    }
}

#[cfg(test)]
mod lifecycle {
    use std::os::fd::IntoRawFd;

    use super::*;

    #[test]
    fn cancellation_retains_close_ownership() -> Result<()> {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair()?;
        let mut socket = IoUringSocket::new(stream.into_raw_fd(), 64, 64)?;
        socket.begin_connect()?;
        assert!(!socket.request_close());
        assert_eq!(socket.phase().superstate(), SocketSuperstate::Teardown);
        assert!(!socket.request_close());
        assert!(socket.connect_completed(true)?);
        assert!(socket.rx_buffer().is_some());
        socket.close_submission_failed()?;
        assert!(socket.request_close());
        assert!(!socket.request_close());
        let fd = socket
            .fd()
            .ok_or_else(|| Error::InvalidState("descriptor missing".into()))?;
        socket.close_started()?;
        assert!(socket.close_started().is_err());
        assert!(socket.close_submission_failed().is_err());
        assert_eq!(socket.fd(), None);
        // SAFETY: This test supplies the close completion and owns its descriptor.
        assert_eq!(unsafe { libc::close(fd) }, 0);
        socket.close_completed()?;
        assert_eq!(socket.state(), SocketState::Closed);
        assert!(socket.rx_buffer().is_none());
        Ok(())
    }
}
