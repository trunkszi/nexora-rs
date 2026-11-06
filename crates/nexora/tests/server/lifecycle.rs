use std::os::fd::IntoRawFd;

use super::*;
use crate::{Request, RequestContext, Responder};

struct Ignore;
impl HttpService for Ignore {
    fn call(&mut self, _: &mut RequestContext, _: Request, _: Responder) -> Result<()> {
        Ok(())
    }
}

#[test]
fn cancelled_close_releases_owned_fd() -> Result<()> {
    let mut ring = Proactor::builder().build()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let local = listener.local_addr()?;
    let _peer = std::net::TcpStream::connect(local)?;
    let (socket, _) = listener.accept()?;
    let fd = socket.into_raw_fd();
    let mut state = State::new(
        ServerConfig::default(),
        Ignore,
        listener.into_raw_fd(),
        local,
    );
    state.accept_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: Both output pointers are exclusive, correctly sized, and initialized before use.
    let rc = unsafe {
        libc::getpeername(
            fd,
            std::ptr::addr_of_mut!(state.accept_addr).cast(),
            &mut state.accept_len,
        )
    };
    assert_eq!(rc, 0);
    state.on_accept(fd)?;
    state.fail_conn(0);
    state.arm_close(&mut ring, 0)?;
    let mut server = HttpServer {
        state: Rc::new(UnsafeCell::new(state)),
    };
    ring.shutdown_with(&mut server)?;
    server.state_mut().apply_completions()?;
    drop(server);
    // SAFETY: F_GETFD only observes the original descriptor number after shutdown.
    let leaked = unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1;
    if leaked {
        // SAFETY: The ring is shut down; no CLOSE ran and this fixture still owns fd.
        unsafe { libc::close(fd) };
    }
    assert!(!leaked, "cancelled server CLOSE leaked fd");
    Ok(())
}

fn connected() -> Result<(HttpServer<Ignore>, std::net::TcpStream, i32)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let local = listener.local_addr()?;
    let peer = std::net::TcpStream::connect(local)?;
    let (socket, _) = listener.accept()?;
    let fd = socket.into_raw_fd();
    let mut state = State::new(
        ServerConfig::default(),
        Ignore,
        listener.into_raw_fd(),
        local,
    );
    state.accept_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    assert_eq!(
        // SAFETY: Output storage is exclusive and sized for sockaddr_storage through the call.
        unsafe {
            libc::getpeername(
                fd,
                std::ptr::addr_of_mut!(state.accept_addr).cast(),
                &mut state.accept_len,
            )
        },
        0
    );
    state.on_accept(fd)?;
    state.io_state.set_shutting_down(true);
    Ok((
        HttpServer {
            state: Rc::new(UnsafeCell::new(state)),
        },
        peer,
        fd,
    ))
}

#[test]
fn send_failure_retires_the_connection() -> Result<()> {
    let mut ring = Proactor::builder().build()?;
    let (mut server, _peer, fd) = connected()?;
    // SAFETY: The fixture owns a connected socket; disabling writes deterministically forces EPIPE.
    assert_eq!(unsafe { libc::shutdown(fd, libc::SHUT_WR) }, 0);
    let state = server.state_mut();
    let conn = state.conns[0]
        .as_mut()
        .ok_or_else(|| Error::InvalidState("missing conn".into()))?;
    conn.pending.extend_from_slice(b"reply");
    state.io_state.set_shutting_down(false);
    state.arm_recv(&mut ring, 0)?;
    state.io_state.set_shutting_down(true);
    state.arm_send(&mut ring, 0)?;
    for attempt in 0..4 {
        ring.submit()?;
        ring.wait_completions(1, Some(std::time::Duration::from_millis(100)), &mut server)?;
        if attempt == 0 {
            assert!(
                server
                    .state()
                    .completions
                    .iter()
                    .any(|c| c.result == -libc::EPIPE),
                "fixture did not receive a real kernel EPIPE"
            );
        }
        server.state_mut().apply_completions()?;
        if server.active_connections() == 0 {
            break;
        }
        server.state_mut().arm(&mut ring)?;
    }
    let stuck = server.active_connections();
    ring.shutdown_with(&mut server)?;
    server.state_mut().apply_completions()?;
    assert_eq!(
        stuck, 0,
        "EPIPE keeps retrying an unsendable pending buffer"
    );
    Ok(())
}

#[test]
fn zero_send_retires_pending_output() -> Result<()> {
    let mut ring = Proactor::builder().build()?;
    let (mut server, _peer, fd) = connected()?;
    let state = server.state_mut();
    let conn = state.conns[0]
        .as_mut()
        .ok_or_else(|| Error::InvalidState("missing conn".into()))?;
    conn.pending.extend_from_slice(b"reply");
    conn.inflight_tx = conn.pending.len();
    conn.io_state.set_send_on(true);
    conn.sock.begin_op()?;
    // A zero-progress send is injected without leaving a real SEND owning the buffer.
    state.completions.push(Completion {
        operation_id: super::super::net::pack(
            state.config.net_subsystem,
            super::super::KIND_SEND,
            0,
        ),
        result: 0,
        flags: 0,
    });
    assert_eq!(state.apply_completions()?, 1);
    let conn = state.conns[0]
        .as_ref()
        .ok_or_else(|| Error::InvalidState("missing conn".into()))?;
    assert!(conn.pending.is_empty(), "zero SEND left unsendable output");
    assert_eq!(conn.inflight_tx, 0);
    assert_eq!(conn.sock.in_flight_ops(), 0);
    assert!(!conn.io_state.send_on());
    assert!(conn.io_state.close_pending());
    state.arm(&mut ring)?;
    let conn = state.conns[0]
        .as_ref()
        .ok_or_else(|| Error::InvalidState("missing closing conn".into()))?;
    assert!(conn.io_state.close_on());
    assert!(!conn.io_state.send_on(), "zero SEND was rearmed");
    ring.submit()?;
    ring.wait_completions(1, Some(std::time::Duration::from_millis(100)), &mut server)?;
    server.state_mut().apply_completions()?;
    let remaining = server.active_connections();
    ring.shutdown_with(&mut server)?;
    assert_eq!(remaining, 0, "zero SEND prevented connection retirement");
    // SAFETY: F_GETFD only observes the retired descriptor number after the close CQE.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    Ok(())
}

#[test]
fn graceful_shutdown_retires_idle_recv() -> Result<()> {
    let mut ring = Proactor::builder().build()?;
    let (mut server, _peer, _fd) = connected()?;
    server.state_mut().io_state.set_shutting_down(false);
    server.state_mut().conns[0]
        .as_mut()
        .ok_or_else(|| Error::InvalidState("missing conn".into()))?
        .mode = crate::server::model::Mode::Http1;
    server.state_mut().arm_accept(&mut ring)?;
    server.state_mut().arm_recv(&mut ring, 0)?;
    ring.submit()?;
    server.initiate_graceful_shutdown(&mut ring)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
    while server.active_connections() != 0 && std::time::Instant::now() < deadline {
        let wait =
            ring.wait_completions(1, Some(std::time::Duration::from_millis(10)), &mut server);
        if let Err(error) = wait
            && !matches!(error, liburing::UringError::Wait(libc::ETIMEDOUT))
        {
            return Err(error.into());
        }
        server.drive(&mut ring)?;
    }
    let stuck = server.active_connections();
    ring.shutdown_with(&mut server)?;
    server.state_mut().apply_completions()?;
    assert_eq!(
        stuck, 0,
        "idle receive is never cancelled by graceful shutdown"
    );
    Ok(())
}
