use std::os::fd::IntoRawFd;

use super::*;

#[test]
fn cancelled_close_releases_owned_fd() -> Result<()> {
    let mut ring = Proactor::builder().build()?;
    let mut client = WebSocketClient::new(
        &mut ring,
        WebSocketClientConfig {
            dns_servers_csv: Some("127.0.0.1".into()),
            ..WebSocketClientConfig::default()
        },
    )?;
    let (socket, _peer) = std::os::unix::net::UnixStream::pair()?;
    let fd = socket.into_raw_fd();
    let id = WebSocketSessionId::new(1);
    let mut owned = Session::new(
        id,
        Uri::parse("ws://127.0.0.1/audit")?,
        &client.config,
        Headers::new(),
        String::new(),
        Box::new(|_, _, _| {}),
    );
    owned.fd = fd;
    owned.state.set_phase(SessionPhase::Teardown);
    client.sessions.insert(id, owned);
    client.pump(&mut ring)?;
    ring.shutdown_with(&mut client)?;
    drop(client);
    // SAFETY: F_GETFD only observes the descriptor number retained by this fixture.
    let leaked = unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1;
    if leaked {
        // SAFETY: No CLOSE ran and the stopped ring cannot reference this fixture fd.
        unsafe { libc::close(fd) };
    }
    assert!(!leaked, "cancelled WebSocket CLOSE leaked fd");
    Ok(())
}

#[test]
fn simultaneous_cancels_have_distinct_ids() -> Result<()> {
    let mut ring = Proactor::builder().build()?;
    let mut client = WebSocketClient::new(
        &mut ring,
        WebSocketClientConfig {
            dns_servers_csv: Some("127.0.0.1".into()),
            ..WebSocketClientConfig::default()
        },
    )?;
    let id = WebSocketSessionId::new(1);
    let mut owned = Session::new(
        id,
        Uri::parse("ws://127.0.0.1/audit")?,
        &client.config,
        Headers::new(),
        String::new(),
        Box::new(|_, _, _| {}),
    );
    owned.cancels = [TAG_RECV, TAG_PING_TIMEOUT]
        .map(|tag| operation_id(client.config.net_subsystem, tag, id))
        .into();
    client.sessions.insert(id, owned);
    let result = client.pump(&mut ring);
    assert!(result.is_ok(), "independent cancels rejected: {result:?}");
    ring.shutdown_with(&mut client)?;
    assert_eq!(client.sessions.get(&id).map(|s| s.inflight), Some(0));
    Ok(())
}

#[test]
fn cancel_retry_preserves_all_remaining_targets() -> Result<()> {
    let mut ring = Proactor::builder().entries(2).build()?;
    let mut client = WebSocketClient::new(
        &mut ring,
        WebSocketClientConfig {
            dns_servers_csv: Some("127.0.0.1".into()),
            ..WebSocketClientConfig::default()
        },
    )?;
    let id = WebSocketSessionId::new(1);
    let mut owned = Session::new(
        id,
        Uri::parse("ws://127.0.0.1/audit")?,
        &client.config,
        Headers::new(),
        String::new(),
        Box::new(|_, _, _| {}),
    );
    let targets: Vec<_> = [TAG_RECV, TAG_SEND, TAG_PING_TIMEOUT]
        .map(|tag| operation_id(client.config.net_subsystem, tag, id))
        .into();
    let mut filled = 0;
    for token in 1..=4096 {
        let op = OperationId::pack(
            SubsystemId::new_unchecked(3),
            OperationPayload::new_unchecked(token),
        );
        let staged = ring.prepare_sqe_with(op, |sqe| {
            // SAFETY: NOP initializes only the exclusive SQE and references no resources.
            unsafe { liburing::ops::prep_nop(sqe) }
        });
        match staged {
            Ok(()) => filled += 1,
            Err(liburing::UringError::SqRingFull) => break,
            Err(error) => return Err(error.into()),
        }
    }
    assert!(filled > 0 && filled < 4096);
    owned.cancels = targets.clone();
    client.sessions.insert(id, owned);
    let result = client.pump(&mut ring);
    assert!(
        matches!(result, Err(Error::Uring(liburing::UringError::SqRingFull))),
        "{result:?}"
    );
    let remaining = client
        .sessions
        .get(&id)
        .map(|s| s.cancels.clone())
        .unwrap_or_default();
    ring.shutdown()?;
    assert_eq!(
        remaining, targets,
        "retry lost a target that was never cancelled"
    );
    Ok(())
}
