use std::{hint::black_box, os::fd::IntoRawFd, time::Instant};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexora::{
    IoUringSocket, OriginKey, OriginPool, PoolConfig, RequestId, Scheme, SubsystemInbox,
    inbox::InboxCommand, pool::OriginState,
};
#[path = "../../nexora-proto/benches/support/mod.rs"]
mod support;
use support::zero_alloc;
fn valid<T, E: std::fmt::Debug>(result: std::result::Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("invalid benchmark fixture: {error:?}"),
    }
}
fn socket() -> IoUringSocket {
    let (stream, _peer) = valid(std::os::unix::net::UnixStream::pair());
    valid(IoUringSocket::new(stream.into_raw_fd(), 64, 64))
}
fn runtime(c: &mut Criterion) {
    let key = OriginKey::new(Scheme::Https, "example.com", 443);
    let mut pool = OriginPool::new(PoolConfig::default());
    let now = Instant::now();
    assert!(pool.add_connection(&key, 1, now));
    pool.mark_idle(&key, 1, now);
    zero_alloc(|| {
        pool.mark_busy(black_box(&key), 1);
        pool.mark_idle(black_box(&key), 1, now);
        black_box(pool.idle_count(&key));
    });
    zero_alloc(|| {
        black_box(pool.set_state(black_box(&key), OriginState::Handshaking));
        black_box(pool.set_state(black_box(&key), OriginState::ReadyHttp2));
    });
    c.bench_function("pool/checkout_checkin", |b| {
        b.iter(|| {
            pool.mark_busy(black_box(&key), 1);
            pool.mark_idle(black_box(&key), 1, now);
            black_box(pool.idle_count(&key));
        })
    });
    c.bench_function("origin/transition_guard", |b| {
        b.iter(|| {
            black_box(
                black_box(OriginState::Connecting)
                    .can_transition_to(black_box(OriginState::ReadyHttp2)),
            )
        })
    });
    c.bench_function("origin/superstate", |b| {
        b.iter(|| black_box(black_box(OriginState::Handshaking).superstate()))
    });
    c.bench_function("pool/ready_transition", |b| {
        b.iter(|| {
            black_box(pool.set_state(black_box(&key), OriginState::Handshaking));
            black_box(pool.set_state(black_box(&key), OriginState::ReadyHttp2));
        })
    });
    let mut active = socket();
    valid(active.begin_connect());
    assert!(!valid(active.connect_completed(true)));
    zero_alloc(|| {
        let socket = black_box(&mut active);
        valid(socket.begin_op());
        black_box(valid(socket.complete_op()));
    });
    c.bench_function("socket/active_io_round", |b| {
        b.iter(|| {
            let socket = black_box(&mut active);
            valid(socket.begin_op());
            black_box(valid(socket.complete_op()));
        })
    });
    // Descriptor creation and final drop are outside the timed cancellation phase.
    // A fixed batch bounds live descriptors independently of Criterion calibration.
    c.bench_function("socket/cancel_connect_drain", |b| {
        b.iter_batched(
            || {
                let mut socket = socket();
                valid(socket.begin_connect());
                socket
            },
            |mut socket| {
                assert!(!socket.request_close());
                assert!(valid(socket.connect_completed(true)));
                valid(socket.close_submission_failed());
                assert!(socket.request_close());
                black_box(socket.state());
                socket
            },
            BatchSize::NumIterations(32),
        )
    });
    let inbox = SubsystemInbox::new();
    for _ in 0..64 {
        inbox.push(InboxCommand::Cancel(RequestId::new(1)));
    }
    while inbox.pop().is_some() {}
    // Queue growth belongs to cold setup; the warmed 64-command bound is reusable.
    zero_alloc(|| {
        for id in 1..=64 {
            inbox.push(InboxCommand::Cancel(RequestId::new(id)));
        }
        let mut count = 0;
        while let Some(command) = inbox.pop() {
            black_box(command);
            count += 1;
        }
        assert_eq!(count, 64);
    });
    c.bench_function("inbox/drain_64", |b| {
        b.iter(|| {
            for id in 1..=64 {
                inbox.push(InboxCommand::Cancel(RequestId::new(id)));
            }
            let mut count = 0;
            while let Some(command) = inbox.pop() {
                black_box(command);
                count += 1;
            }
            assert_eq!(count, 64);
        })
    });
}
criterion_group!(benches, runtime, session_guards);
criterion_main!(benches);

struct UpgradeOnly;
impl nexora::HttpService for UpgradeOnly {
    fn call(
        &mut self,
        _: &mut nexora::RequestContext,
        _: nexora::Request,
        responder: nexora::Responder,
    ) -> nexora::Result<()> {
        responder.respond(nexora::Response::new(nexora::StatusCode::NOT_FOUND))
    }
}
struct IgnoreMessages;
impl nexora::WebSocketUpgradeHandler for IgnoreMessages {
    fn on_message(
        &mut self,
        _: &mut nexora::WebSocketServerSession,
        _: nexora::WebSocketMessage,
    ) -> nexora::Result<()> {
        Ok(())
    }
}
fn session_guards(c: &mut Criterion) {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use nexora::{
        Headers, HttpServer, Proactor, ServerConfig, SubsystemId, WebSocketClient,
        websocket_client::WebSocketClientConfig,
    };
    let mut ring = valid(Proactor::builder().build());
    let mut server = valid(HttpServer::bind(
        &mut ring,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ServerConfig {
            net_subsystem: SubsystemId::new_unchecked(3),
            ..ServerConfig::default()
        },
        UpgradeOnly,
    ))
    .with_websocket_handler("/ws", IgnoreMessages);
    let mut client = valid(WebSocketClient::new(
        &mut ring,
        WebSocketClientConfig {
            dns_subsystem: SubsystemId::new_unchecked(1),
            net_subsystem: SubsystemId::new_unchecked(2),
            dns_servers_csv: Some("127.0.0.1".to_owned()),
            ..WebSocketClientConfig::default()
        },
    ));
    let url = format!("ws://127.0.0.1:{}/ws", server.local_addr().port());
    let session = valid(
        client.connect(&mut ring, &url, Headers::new(), |_, _, result| {
            valid(result)
        }),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while !client.is_open(session) {
        assert!(Instant::now() < deadline, "loopback upgrade timed out");
        valid(server.drive(&mut ring));
        valid(client.drive_with(&mut ring, &mut server));
    }
    // Handshake and ring work are cold setup; only the real session guard is timed.
    zero_alloc(|| assert!(client.is_open(black_box(session))));
    c.bench_function("session/open_guard", |b| {
        b.iter(|| black_box(client.is_open(black_box(session))))
    });
    valid(client.close(&mut ring, session, None));
    zero_alloc(|| assert!(!client.is_open(black_box(session))));
    c.bench_function("session/closing_guard", |b| {
        b.iter(|| black_box(client.is_open(black_box(session))))
    });
    valid(server.initiate_graceful_shutdown(&mut ring));
    let deadline = Instant::now() + Duration::from_secs(3);
    while client.active_session_count() != 0 || server.active_connections() != 0 {
        assert!(Instant::now() < deadline, "loopback close did not retire");
        valid(server.drive(&mut ring));
        valid(client.drive_with(&mut ring, &mut server));
    }
}
