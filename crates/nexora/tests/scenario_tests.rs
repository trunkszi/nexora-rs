#![feature(tcp_linger)]

mod support;

use std::{
    cell::{Cell, RefCell},
    io::{ErrorKind, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    rc::Rc,
    time::Duration,
};

use nexora::{
    Bytes, BytesMut, Headers, HttpClient, HttpServer, Method, Request, WebSocketClient,
    WebSocketMessage,
    proto::{
        Http1ClientCodec, Http1ClientConfig, Http2Config, Http2Connection, Http2Event, Http2Frame,
        Http2Role, Http2Settings, WebSocketCodec, WebSocketFrame, WebSocketOpcode,
        http2::{DEFAULT_MAX_FRAME_SIZE, decode_frame, encode_frame},
    },
    websocket_client::WebSocketEvent,
};
use support::{
    DnsAction, DnsPlan, Gate, GateMode, IntoCheck, MockDns, Slot, TestResult, WebSocketEcho, check,
    client_config, drive_until, proactor, server_config, websocket_config,
};

fn chunked_body(raw: &[u8], step: usize) -> std::result::Result<Vec<u8>, String> {
    let mut codec = Http1ClientCodec::new(Http1ClientConfig::default());
    let mut buf = BytesMut::new();
    for piece in raw.chunks(step.max(1)) {
        buf.extend_from_slice(piece);
        if let Some((response, _)) = codec.decode_response(&mut buf, Method::Get).t()? {
            return Ok(response.body.as_slice().to_vec());
        }
    }
    Err(String::from("chunked response did not complete"))
}
fn http2_frames(raw: &[u8], step: usize) -> std::result::Result<Vec<Http2Frame>, String> {
    let mut buf = BytesMut::new();
    let mut frames = Vec::new();
    for piece in raw.chunks(step.max(1)) {
        buf.extend_from_slice(piece);
        while let Some(frame) = decode_frame(&mut buf, DEFAULT_MAX_FRAME_SIZE).t()? {
            frames.push(frame);
        }
    }
    check(buf.is_empty(), "http2 frame tail was left over")?;
    Ok(frames)
}
fn websocket_messages(
    raw: &[u8],
    step: usize,
) -> std::result::Result<Vec<WebSocketMessage>, String> {
    let mut codec = WebSocketCodec::server_default();
    let mut buf = BytesMut::new();
    let mut messages = Vec::new();
    for piece in raw.chunks(step.max(1)) {
        buf.extend_from_slice(piece);
        while let Some(message) = codec.decode_message(&mut buf).t()? {
            messages.push(message);
        }
    }
    Ok(messages)
}
fn settle(
    left: &mut Http2Connection,
    right: &mut Http2Connection,
) -> std::result::Result<(Vec<Http2Event>, Vec<Http2Event>), String> {
    let mut left_events = Vec::new();
    let mut right_events = Vec::new();
    for _ in 0..32 {
        let mut outbound = BytesMut::new();
        left.take_tx_bytes(&mut outbound);
        right.feed_bytes(&mut outbound).t()?;
        check(outbound.is_empty(), "right peer left a partial frame")?;
        while let Some(event) = right.poll_event() {
            right_events.push(event);
        }
        let mut inbound = BytesMut::new();
        right.take_tx_bytes(&mut inbound);
        left.feed_bytes(&mut inbound).t()?;
        check(inbound.is_empty(), "left peer left a partial frame")?;
        while let Some(event) = left.poll_event() {
            left_events.push(event);
        }
        if !left.has_tx_bytes() && !right.has_tx_bytes() {
            return Ok((left_events, right_events));
        }
    }
    Err(String::from("http2 peers did not settle"))
}

fn deliver_except_settings_ack(
    client: &mut Http2Connection,
    server: &mut Http2Connection,
) -> TestResult {
    let mut outbound = BytesMut::new();
    client.take_tx_bytes(&mut outbound);
    let raw = outbound.as_ref();
    let mut forward = BytesMut::new();
    let mut offset = 0usize;
    while offset + 9 <= raw.len() {
        let length = (usize::from(raw[offset]) << 16)
            | (usize::from(raw[offset + 1]) << 8)
            | usize::from(raw[offset + 2]);
        let end = offset
            .checked_add(9 + length)
            .ok_or_else(|| String::from("frame length overflow"))?;
        if end > raw.len() {
            return Err(String::from("client left a partial frame"));
        }
        let settings_ack = raw[offset + 3] == 4 && raw[offset + 4] & 1 == 1;
        if !settings_ack {
            forward.extend_from_slice(&raw[offset..end]);
        }
        offset = end;
    }
    check(offset == raw.len(), "client left a partial frame")?;
    server.feed_bytes(&mut forward).t()?;
    Ok(())
}
#[test]
fn sc_01_trickle_and_burst_reassemble_the_same_bytes() -> TestResult {
    let _exclusive = support::exclusive();
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    check(
        chunked_body(chunked, 1)? == chunked_body(chunked, chunked.len())?,
        "http1 trickle matches the burst",
    )?;
    let mut wire = BytesMut::new();
    encode_frame(
        &Http2Frame::Headers {
            stream_id: 1,
            end_stream: false,
            end_headers: false,
            header_block: Bytes::copy_from_slice(b"ab"),
        },
        &mut wire,
    )
    .t()?;
    encode_frame(
        &Http2Frame::Continuation {
            stream_id: 1,
            end_headers: true,
            header_block: Bytes::copy_from_slice(b"cd"),
        },
        &mut wire,
    )
    .t()?;
    encode_frame(
        &Http2Frame::Data {
            stream_id: 1,
            end_stream: true,
            data: Bytes::copy_from_slice(b"xyz"),
        },
        &mut wire,
    )
    .t()?;
    check(
        http2_frames(wire.as_slice(), 1)? == http2_frames(wire.as_slice(), wire.len())?,
        "http2 trickle matches the burst",
    )?;
    let mut client = WebSocketCodec::client_default();
    let mut frames = BytesMut::new();
    client
        .encode_frame(
            &WebSocketFrame {
                fin: false,
                opcode: WebSocketOpcode::Text,
                payload: Bytes::copy_from_slice(b"hel"),
            },
            &mut frames,
        )
        .t()?;
    client
        .encode_frame(
            &WebSocketFrame {
                fin: true,
                opcode: WebSocketOpcode::Continuation,
                payload: Bytes::copy_from_slice(b"lo"),
            },
            &mut frames,
        )
        .t()?;
    let slow = websocket_messages(frames.as_slice(), 1)?;
    let fast = websocket_messages(frames.as_slice(), frames.len())?;
    check(slow == fast, "websocket trickle matches the burst")?;
    check(
        slow == vec![WebSocketMessage::Text(String::from("hello"))],
        "fragmented text reassembles",
    )
}
#[test]
fn sc_02_dns_drop_truncate_and_failover() -> TestResult {
    let _exclusive = support::exclusive();
    let live = Ipv4Addr::LOCALHOST;
    let dead = Ipv4Addr::new(127, 0, 0, 2);
    let dns = MockDns::spawn(DnsPlan::script(DnsAction::Family {
        v4: vec![dead, live],
    }))
    .t()?;
    let mut ring = proactor().t()?;
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let port = server.local_addr().port();
    let mut config = client_config(1, 2).t()?;
    config.dns_servers_csv = Some(dns.servers_csv());
    let mut client = HttpClient::new(&mut ring, config).t()?;
    let slot = Slot::new();
    let done = slot.clone();
    let request = Request::get(&format!("http://live.test:{port}/echo")).t()?;
    client
        .submit(&mut ring, request, move |_ctx, _id, result| {
            done.set(result)
        })
        .t()?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(slot.calls() > 0)
        },
        Duration::from_secs(12),
    )
    .t()?;
    check(finished, "dns failover timed out")?;
    check(dns.dropped() >= 1, "udp query was dropped")?;
    check(dns.tcp_queries() >= 1, "truncated udp fell back to tcp")?;
    let response = slot
        .take()
        .ok_or_else(|| String::from("missing failover response"))?
        .t()?;
    check(
        response.body.as_slice() == b"ok",
        "failover reached the live address",
    )
}
#[test]
fn sc_03_stream_cap_and_http1_fanout() -> TestResult {
    let _exclusive = support::exclusive();
    let settings = Http2Settings {
        enable_push: false,
        max_concurrent_streams: 8,
        ..Http2Settings::default()
    };
    let mut server = Http2Connection::new(
        Http2Role::Server,
        Http2Config {
            local_settings: settings,
            max_body_size: 1024,
        },
    );
    let mut client = Http2Connection::client_default();
    settle(&mut client, &mut server)?;
    let mut opened = 0usize;
    for index in 0..16 {
        let request = Request::get(&format!("https://localhost/s/{index}")).t()?;
        if client.submit_request(&request).is_ok() {
            opened += 1;
        }
    }
    check(
        opened == 8,
        "http2 accepted more than the advertised stream cap",
    )?;
    let mut ring = proactor().t()?;
    let mut limits = server_config(3).t()?;
    limits.max_body_size = 8;
    let mut http = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        limits,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let port = http.local_addr().port();
    let mut config = client_config(1, 2).t()?;
    config.pool.max_connections_per_origin = 4;
    let mut caller = HttpClient::new(&mut ring, config).t()?;
    let done = Rc::new(Cell::new(0u32));
    for _ in 0..16 {
        let done = Rc::clone(&done);
        let request = Request::get(&format!("http://127.0.0.1:{port}/echo")).t()?;
        caller
            .submit(&mut ring, request, move |_ctx, _id, result| {
                if result.is_ok() {
                    done.set(done.get().saturating_add(1));
                }
            })
            .t()?;
    }
    let finished = drive_until(
        &mut ring,
        |ring| {
            http.drive(ring)?;
            caller.drive_with(ring, &mut http)?;
            Ok(done.get() == 16)
        },
        Duration::from_secs(4),
    )
    .t()?;
    check(finished, "http1 fan-out did not finish 16 requests")?;
    check(
        caller.idle_connection_count(&nexora::OriginKey::new(
            nexora::proto::Scheme::Http,
            "127.0.0.1",
            port,
        )) <= 4,
        "idle pool stayed inside the connection cap",
    )?;
    let oversized = Slot::new();
    let oversized_done = oversized.clone();
    caller
        .submit(
            &mut ring,
            Request::post(&format!("http://127.0.0.1:{port}/echo"), vec![1u8; 32]).t()?,
            move |_ctx, _id, result| {
                oversized_done.set(result.map(|response| response.status.as_u16()))
            },
        )
        .t()?;
    let limited = drive_until(
        &mut ring,
        |ring| {
            http.drive(ring)?;
            caller.drive_with(ring, &mut http)?;
            Ok(oversized.calls() > 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(limited, "oversized body timed out")?;
    check(
        matches!(oversized.take(), Some(Ok(413))),
        "max_body_size is rejected with 413",
    )
}
#[test]
fn sc_04_negative_window_recovers_with_window_update() -> TestResult {
    let _exclusive = support::exclusive();
    let mut client = Http2Connection::client_default();
    let mut server = Http2Connection::server_default();
    settle(&mut client, &mut server)?;
    let narrow = Http2Settings {
        enable_push: false,
        initial_window_size: 50,
        ..Http2Settings::default()
    };
    let mut shrink = BytesMut::new();
    encode_frame(
        &Http2Frame::Settings {
            ack: false,
            settings: narrow,
        },
        &mut shrink,
    )
    .t()?;
    client.feed_bytes(&mut shrink).t()?;
    let mut ack = BytesMut::new();
    client.take_tx_bytes(&mut ack);
    let request = Request::post("https://localhost/echo", vec![7u8; 100]).t()?;
    let stream_id = client.submit_request(&request).t()?;
    check(
        client
            .stream_send_window(stream_id)
            .ok_or_else(|| String::from("missing stream window"))?
            == 0,
        "the first 50 bytes consumed the narrowed window",
    )?;
    let closed = Http2Settings {
        enable_push: false,
        initial_window_size: 0,
        ..Http2Settings::default()
    };
    shrink.clear();
    encode_frame(
        &Http2Frame::Settings {
            ack: false,
            settings: closed,
        },
        &mut shrink,
    )
    .t()?;
    client.feed_bytes(&mut shrink).t()?;
    let after = client
        .stream_send_window(stream_id)
        .ok_or_else(|| String::from("window disappeared"))?;
    check(after < 0, "initial window shrink drove the stream negative")?;
    check(after == -50, "the unsent tail stays blocked at -50")?;
    deliver_except_settings_ack(&mut client, &mut server)?;
    let mut early_body = false;
    while let Some(event) = server.poll_event() {
        if let Http2Event::RequestReceived { request, .. } = event
            && request.body.len() == 100
        {
            early_body = true;
        }
    }
    check(
        !early_body,
        "the body arrived while the send window was negative",
    )?;
    let mut update = BytesMut::new();
    encode_frame(
        &Http2Frame::WindowUpdate {
            stream_id,
            increment: 256,
        },
        &mut update,
    )
    .t()?;
    client.feed_bytes(&mut update).t()?;
    let restored = client
        .stream_send_window(stream_id)
        .ok_or_else(|| String::from("window missing after update"))?;
    check(
        restored == after + 256 - 50,
        "window update paid for the blocked tail",
    )?;
    deliver_except_settings_ack(&mut client, &mut server)?;
    let mut saw_body = false;
    while let Some(event) = server.poll_event() {
        if let Http2Event::RequestReceived { request, .. } = event
            && request.body.len() == 100
        {
            saw_body = true;
        }
    }
    check(saw_body, "window update released the blocked body")
}
#[test]
fn sc_05_reset_mid_response_then_healthy_origin() -> TestResult {
    let _exclusive = support::exclusive();
    let listener = TcpListener::bind(support::ephemeral()).t()?;
    listener.set_nonblocking(true).t()?;
    let broken_port = listener.local_addr().t()?.port();
    let mut ring = proactor().t()?;
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let good_port = server.local_addr().port();
    let mut client = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let broken = Slot::new();
    let broken_done = broken.clone();
    let request = Request::get(&format!("http://127.0.0.1:{broken_port}/partial")).t()?;
    client
        .submit(&mut ring, request, move |_ctx, _id, result| {
            broken_done.set(result.is_err())
        })
        .t()?;
    let mut reset = false;
    let saw = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            if !reset && let Ok((mut stream, _)) = listener.accept() {
                let partial = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nhi");
                let linger = stream.set_linger(Some(Duration::ZERO));
                drop(stream);
                reset = partial.is_ok() && linger.is_ok();
            }
            Ok(broken.calls() > 0 && reset)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(saw, "reset peer did not finish the in-flight request")?;
    check(broken.take() == Some(true), "reset request failed")?;
    let healthy = Slot::new();
    let healthy_done = healthy.clone();
    let next = Request::get(&format!("http://127.0.0.1:{good_port}/echo")).t()?;
    client
        .submit(&mut ring, next, move |_ctx, _id, result| {
            healthy_done.set(result)
        })
        .t()?;
    let recovered = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(healthy.calls() > 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(recovered, "healthy origin timed out")?;
    let response = healthy
        .take()
        .ok_or_else(|| String::from("missing recovery"))?
        .t()?;
    check(
        response.body.as_slice() == b"ok",
        "later request used a fresh connection",
    )
}
#[test]
fn sc_06_websocket_ticker_ping_close_and_resubscribe() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let echo = WebSocketEcho::new();
    let texts = echo.texts();
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?
    .with_websocket_handler("/stream", echo);
    let port = server.local_addr().port();
    let mut websocket = WebSocketClient::new(&mut ring, websocket_config(1, 2).t()?).t()?;
    let events = Rc::new(RefCell::new(Vec::new()));
    let url = format!("ws://127.0.0.1:{port}/stream");
    let session = websocket
        .connect(&mut ring, &url, Headers::new(), |_ctx, _id, _result| {})
        .t()?;
    let events_handler = Rc::clone(&events);
    websocket
        .set_message_handler(session, move |_ctx, _socket, event| {
            events_handler.borrow_mut().push(event)
        })
        .t()?;
    let opened = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            websocket.drive_with(ring, &mut server)?;
            Ok(websocket.is_open(session))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(opened, "websocket upgrade timed out")?;
    for index in 0..64u32 {
        websocket
            .send_text(&mut ring, session, format!("t{index}"))
            .t()?;
        if index % 16 == 15 {
            let ready = drive_until(
                &mut ring,
                |ring| {
                    server.drive(ring)?;
                    websocket.drive_with(ring, &mut server)?;
                    Ok(texts.borrow().len() > index as usize)
                },
                Duration::from_secs(2),
            )
            .t()?;
            check(ready, "ticker stalled")?;
        }
    }
    websocket
        .ping(&mut ring, session, Bytes::copy_from_slice(b"hb"))
        .t()?;
    let pinged = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            websocket.drive_with(ring, &mut server)?;
            Ok(events
                .borrow()
                .iter()
                .any(|event| matches!(event, WebSocketEvent::Pong(_))))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(pinged, "pong was not observed")?;
    websocket
        .close(
            &mut ring,
            session,
            Some(nexora::WebSocketCloseFrame {
                code: nexora::WebSocketCloseCode::Normal,
                reason: String::from("done"),
            }),
        )
        .t()?;
    let closed = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            websocket.drive_with(ring, &mut server)?;
            Ok(!websocket.is_open(session) && websocket.active_session_count() == 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(closed, "close was not observed")?;
    let again = websocket
        .connect(&mut ring, &url, Headers::new(), |_ctx, _id, _result| {})
        .t()?;
    websocket
        .set_message_handler(again, |_ctx, _socket, _event| {})
        .t()?;
    let reopened = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            websocket.drive_with(ring, &mut server)?;
            Ok(websocket.is_open(again))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(reopened, "resubscribe upgrade timed out")?;
    websocket.send_text(&mut ring, again, "subscribe").t()?;
    let acked = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            websocket.drive_with(ring, &mut server)?;
            Ok(texts.borrow().iter().any(|text| text == "subscribe"))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(acked, "resubscribe was not observed")
}
#[test]
fn sc_07_slowloris_isolation_and_cross_origin_redirect() -> TestResult {
    let _exclusive = support::exclusive();
    let threads = support::thread_count().t()?;
    let mut ring = proactor().t()?;
    let upstream = Gate::new(GateMode::Echo);
    let mut origin = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(6).t()?,
        upstream,
    )
    .t()?;
    let origin_port = origin.local_addr().port();
    let edge = Gate::new(GateMode::Redirect);
    edge.set_location(format!("http://127.0.0.1:{origin_port}/echo"));
    let mut server =
        HttpServer::bind(&mut ring, support::ephemeral(), server_config(3).t()?, edge).t()?;
    let port = server.local_addr().port();
    let mut stall = TcpStream::connect(server.local_addr()).t()?;
    stall.set_nonblocking(true).t()?;
    let wrote = stall.write(b"G");
    check(
        wrote.is_ok()
            || wrote
                .as_ref()
                .is_err_and(|error| error.kind() == ErrorKind::WouldBlock),
        "stall write was attempted",
    )?;
    let mut client = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let healthy = Slot::new();
    let healthy_done = healthy.clone();
    let request = Request::get(&format!("http://127.0.0.1:{port}/echo")).t()?;
    client
        .submit(&mut ring, request, move |_ctx, _id, result| {
            healthy_done.set(result)
        })
        .t()?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            origin.drive(ring)?;
            client.drive_with(
                ring,
                &mut nexora::CompletionRoutes::new(&mut server, &mut origin),
            )?;
            Ok(healthy.calls() > 0)
        },
        Duration::from_secs(3),
    )
    .t()?;
    check(finished, "healthy request stalled behind the slow header")?;
    let response = healthy
        .take()
        .ok_or_else(|| String::from("missing redirect"))?
        .t()?;
    check(
        response.body.as_slice() == b"ok",
        "redirect followed to the echo body",
    )?;
    check(
        support::thread_count().t()? == threads,
        "slowloris did not start another thread",
    )?;
    drop(stall);
    Ok(())
}
#[test]
fn sc_connection_error_writes_goaway() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let mut peer = TcpStream::connect(server.local_addr()).t()?;
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0]);
    peer.write_all(&payload).t()?;
    peer.set_nonblocking(true).t()?;
    let mut poller = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let mut received = Vec::new();
    let finished = drive_until(
        &mut ring,
        |ring| {
            match server.drive(ring) {
                Ok(_) | Err(nexora::Error::Proto(_)) => {}
                Err(error) => return Err(error),
            }
            poller.drive_with(ring, &mut server)?;
            let mut tmp = [0u8; 2048];
            match peer.read(&mut tmp) {
                Ok(0) => {}
                Ok(n) => received.extend_from_slice(&tmp[..n]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(nexora::Error::Io(error)),
            }
            let mut view = BytesMut::new();
            view.extend_from_slice(&received);
            let mut goaway = false;
            while let Some(frame) =
                decode_frame(&mut view, DEFAULT_MAX_FRAME_SIZE).map_err(nexora::Error::from)?
            {
                if matches!(frame, Http2Frame::GoAway { .. }) {
                    goaway = true;
                }
            }
            Ok(goaway)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(finished, "connection error did not produce GOAWAY")
}
#[test]
fn sc_coalesced_upgrade_delivers_websocket_frame() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let echo = WebSocketEcho::new();
    let texts = echo.texts();
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?
    .with_websocket_handler("/ws", echo);
    let port = server.local_addr().port();
    let mut peer = TcpStream::connect(server.local_addr()).t()?;
    let mut payload = format!(
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: \
         Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \
         dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
    .into_bytes();
    let mut frame = BytesMut::new();
    WebSocketCodec::client_default()
        .encode_message(&WebSocketMessage::Text(String::from("hi")), &mut frame)
        .t()?;
    payload.extend_from_slice(frame.as_ref());
    peer.write_all(&payload).t()?;
    peer.set_nonblocking(true).t()?;
    let mut poller = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let saw = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            poller.drive_with(ring, &mut server)?;
            Ok(texts.borrow().iter().any(|text| text == "hi"))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(saw, "coalesced websocket frame was not delivered")
}
