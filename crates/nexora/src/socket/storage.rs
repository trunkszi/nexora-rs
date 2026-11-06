//! Socket allocation and final descriptor ownership.

use uarch::prelude::*;

use super::{Error, IoUringSocket, RawFd, Result};

#[cold_sink]
pub(super) fn count_overflow() -> Error {
    Error::InvalidState("in-flight operation count overflowed".to_owned())
}

#[cold_sink]
pub(super) fn empty_retirement(operation: &str) -> Error {
    Error::InvalidState(format!(
        "{operation} completion arrived with no operation in flight"
    ))
}

/// Largest buffer capacity that `Vec` accepts instead of reporting a capacity
/// overflow.
const MAX_BUFFER_CAPACITY: usize = isize::MAX as usize;

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
        if self.in_flight_ops() > 0 {
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

pub(super) fn validate_capacities(rx_capacity: usize, tx_capacity: usize) -> Result<()> {
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

pub(super) fn zeroed_buffer(capacity: usize) -> Box<[u8]> {
    vec![0u8; capacity].into_boxed_slice()
}

/// Runs one descriptor status call, retrying after `EINTR`.
///
/// # Errors
/// Returns [`Error::Io`] for any failure other than interruption.
pub(super) fn fcntl_status(
    fd: RawFd,
    command: libc::c_int,
    argument: libc::c_int,
) -> Result<libc::c_int> {
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
