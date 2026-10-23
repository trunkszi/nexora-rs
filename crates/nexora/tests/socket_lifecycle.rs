//! Socket and pinned-storage lifecycle through the public interface.

use std::os::fd::RawFd;

use nexora::{IoUringSocket, Result, SocketState};

fn fcntl_status(fd: RawFd, command: libc::c_int, argument: libc::c_int) -> std::io::Result<i32> {
    // SAFETY: Tests query the status of their retained descriptor; no pointer operands.
    let status = unsafe { libc::fcntl(fd, command, argument) };
    if status < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(status)
    }
}

fn pair() -> (RawFd, RawFd) {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` points to two writable slots that `socketpair` fills.
    let result = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(result, 0, "socketpair failed");
    (fds[0], fds[1])
}

fn io_socket() -> Result<(IoUringSocket, RawFd)> {
    let (fd, peer) = pair();
    let socket = IoUringSocket::new(fd, 64, 64)?;
    Ok((socket, peer))
}

fn connected(socket: &mut IoUringSocket) -> Result<()> {
    socket.begin_connect()?;
    assert!(!socket.connect_completed(true)?);
    Ok(())
}

fn close_fd(fd: RawFd) {
    // SAFETY: `fd` is a live descriptor owned by the caller and closed once.
    unsafe {
        libc::close(fd);
    }
}

/// Simulates the close CQE and then closes the test's still-open descriptor.
fn complete_close(socket: &mut IoUringSocket) -> Result<()> {
    let raw = socket.fd();
    socket.close_started()?;
    socket.close_completed()?;
    if let Some(fd) = raw {
        close_fd(fd);
    }
    Ok(())
}

/// Polls the peer end: `true` means the socket end was closed.
fn peer_is_closed(peer: RawFd) -> bool {
    let mut item = libc::pollfd {
        fd: peer,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `item` is one initialized pollfd and the zero timeout makes
    // the call non-blocking.
    let ready = unsafe { libc::poll(&mut item, 1, 0) };
    ready > 0 && item.revents & (libc::POLLIN | libc::POLLHUP) != 0
}

#[test]
fn construction_sets_nonblocking_and_drop_closes() -> Result<()> {
    let (fd, peer) = pair();
    assert!(fcntl_status(fd, libc::F_GETFL, 0).is_ok_and(|f| f & libc::O_NONBLOCK == 0));
    let socket = IoUringSocket::new(fd, 64, 64)?;
    assert_eq!(socket.state(), SocketState::Idle);
    assert_eq!(socket.rx_buffer().map(|b| b.len()), Some(64));
    assert!(fcntl_status(fd, libc::F_GETFL, 0).is_ok_and(|f| f & libc::O_NONBLOCK != 0));
    drop(socket);
    assert!(peer_is_closed(peer));
    close_fd(peer);
    Ok(())
}

#[test]
fn connect_lifecycle() -> Result<()> {
    let (mut socket, peer) = io_socket()?;
    assert!(socket.begin_op().is_err(), "op before connect");
    socket.begin_connect()?;
    assert_eq!(socket.state(), SocketState::Connecting);
    assert_eq!(socket.in_flight_ops(), 1);
    assert!(socket.begin_connect().is_err());
    assert!(!socket.connect_completed(true)?);
    assert_eq!(socket.state(), SocketState::Connected);
    socket.begin_op()?;
    assert!(!socket.complete_op()?);
    drop(socket);
    close_fd(peer);
    Ok(())
}

#[test]
fn connect_failure_requires_a_close() -> Result<()> {
    let (mut socket, peer) = io_socket()?;
    socket.begin_connect()?;
    assert!(socket.connect_completed(false)?);
    assert_eq!(socket.state(), SocketState::Closing);
    assert!(socket.close_completed().is_err());
    socket.close_started()?;
    assert!(socket.close_started().is_err());
    let raw = socket.fd();
    socket.close_completed()?;
    assert_eq!(socket.state(), SocketState::Closed);
    assert!(socket.fd().is_none() && socket.rx_buffer().is_none());
    assert!(socket.close_completed().is_err());
    if let Some(fd) = raw {
        close_fd(fd);
    }
    close_fd(peer);
    Ok(())
}

#[test]
fn close_waits_for_the_last_operation() -> Result<()> {
    let (mut socket, peer) = io_socket()?;
    connected(&mut socket)?;
    socket.begin_op()?;
    let address = socket.rx_buffer().map(|b| b.as_ptr());
    assert!(!socket.request_close());
    assert_eq!(socket.state(), SocketState::Cancelling);
    assert!(socket.close_started().is_err());
    assert!(socket.close_completed().is_err());
    assert!(!socket.request_close());
    assert!(socket.rx_buffer().is_some() && socket.tx_buffer().is_some());
    assert_eq!(socket.rx_buffer().map(|b| b.as_ptr()), address);
    assert!(socket.complete_op()?);
    assert_eq!(socket.state(), SocketState::Closing);
    let raw = socket.fd();
    socket.close_started()?;
    assert!(socket.close_submitted() && socket.fd().is_none());
    socket.close_completed()?;
    assert!(socket.rx_buffer().is_none() && socket.tx_buffer().is_none());
    if let Some(fd) = raw {
        close_fd(fd);
    }
    close_fd(peer);
    Ok(())
}

#[test]
fn cancel_retains_buffers_until_the_last_completion() -> Result<()> {
    let (mut socket, peer) = io_socket()?;
    assert!(socket.request_cancel());
    assert_eq!(socket.state(), SocketState::Closing);
    assert!(socket.request_close());
    complete_close(&mut socket)?;
    close_fd(peer);

    let (mut socket, peer) = io_socket()?;
    connected(&mut socket)?;
    socket.begin_op()?;
    socket.begin_op()?;
    assert!(!socket.request_cancel());
    assert_eq!(socket.state(), SocketState::Cancelling);
    assert!(socket.begin_op().is_err());
    assert!(socket.renew_buffers(16, 16).is_err());
    assert!(socket.rx_buffer().is_some() && socket.tx_buffer().is_some());
    assert!(!socket.complete_op()?);
    assert_eq!(socket.state(), SocketState::Cancelling);
    assert!(socket.complete_op()?);
    assert_eq!(socket.state(), SocketState::Closing);
    assert!(socket.rx_buffer().is_some());
    complete_close(&mut socket)?;
    assert!(socket.rx_buffer().is_none());
    close_fd(peer);
    Ok(())
}

#[test]
fn spurious_completions_are_rejected() -> Result<()> {
    let (mut socket, peer) = io_socket()?;
    socket.begin_connect()?;
    assert!(socket.complete_op().is_err());
    assert_eq!(socket.state(), SocketState::Connecting);
    assert!(!socket.connect_completed(true)?);
    assert!(socket.connect_completed(true).is_err());
    assert!(socket.complete_op().is_err());
    assert_eq!(socket.state(), SocketState::Connected);
    socket.begin_op()?;
    assert!(!socket.complete_op()?);
    assert!(socket.complete_op().is_err());
    assert_eq!(socket.in_flight_ops(), 0);
    drop(socket);
    close_fd(peer);
    Ok(())
}

#[test]
fn double_close_is_rejected_and_staging_can_retry() -> Result<()> {
    let (mut socket, peer) = io_socket()?;
    assert!(socket.request_close());
    assert!(!socket.request_close());
    socket.close_submission_failed()?;
    assert!(socket.request_close());
    let raw = socket.fd();
    socket.close_started()?;
    assert!(socket.close_submission_failed().is_err());
    socket.close_completed()?;
    assert!(socket.close_started().is_err() && socket.close_completed().is_err());
    if let Some(fd) = raw {
        close_fd(fd);
    }
    close_fd(peer);
    Ok(())
}

#[test]
fn renew_buffers_rules() -> Result<()> {
    let (mut socket, peer) = io_socket()?;
    socket.renew_buffers(16, 32)?;
    assert_eq!(socket.rx_buffer().map(|b| b.len()), Some(16));
    assert!(socket.renew_buffers(0, 32).is_err());
    assert!(socket.renew_buffers(32, 0).is_err());
    assert!(socket.renew_buffers(usize::MAX, 32).is_err());
    let before = socket.rx_buffer().map(|b| b.as_ptr());
    socket.renew_buffers(128, 128)?;
    assert_ne!(socket.rx_buffer().map(|b| b.as_ptr()), before);
    connected(&mut socket)?;
    socket.begin_op()?;
    assert!(socket.renew_buffers(64, 64).is_err());
    assert!(!socket.complete_op()?);
    assert!(socket.request_close());
    assert!(socket.renew_buffers(64, 64).is_err());
    drop(socket);
    close_fd(peer);

    let (fd, peer) = pair();
    assert!(IoUringSocket::new(fd, 0, 64).is_err());
    assert!(IoUringSocket::new(fd, 64, 0).is_err());
    assert!(IoUringSocket::new(fd, usize::MAX, 64).is_err());
    close_fd(fd);
    close_fd(peer);
    Ok(())
}

#[test]
fn drop_close_ownership() -> Result<()> {
    let (fd, peer) = pair();
    let mut socket = IoUringSocket::new(fd, 64, 64)?;
    assert!(socket.request_close());
    socket.close_started()?;
    drop(socket);
    assert!(fcntl_status(fd, libc::F_GETFL, 0).is_ok());
    close_fd(fd);
    close_fd(peer);

    let (mut socket, peer) = io_socket()?;
    socket.begin_connect()?;
    drop(socket);
    assert!(peer_is_closed(peer));
    close_fd(peer);
    Ok(())
}
