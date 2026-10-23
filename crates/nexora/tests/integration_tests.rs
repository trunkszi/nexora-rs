mod support;

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use nexora::{
    AlpnProtocol, Bytes, BytesMut, HeaderMap, HeaderMapExt, Http2ErrorCode, Http2Settings, Method,
    ProtoError, Request, RequestContext, Response, RestRequest, StatusCode, TlsClientConfig,
    TlsServerConfig, WebSocketFrame, WebSocketMessage, WebSocketOpcode, headers, http_service,
    http2_headers,
    proto::{
        Http1ClientCodec, Http1ClientConfig, Http1KeepAlive, TlsSession, WebSocketCodec,
        WebSocketHandshake,
        http2::{
            DEFAULT_MAX_FRAME_SIZE, HpackDecoder, HpackEncoder, Http2Connection, Http2Frame,
            Http2FrameType, decode_frame, encode_frame, huffman_decode, huffman_encode,
            huffman_encoded_len,
        },
    },
};
use support::{
    DnsPlan, IntoCheck, MockDns, TestResult, check, client_config, drive_until, proactor,
};

fn show(error: impl ToString) -> String {
    error.to_string()
}

fn shared_pointer(prefix: &[u8], later: &[u8], distance: usize) -> bool {
    let base = prefix.as_ptr() as usize;
    later.as_ptr() as usize == base + distance
}

#[test]
fn it_01_bytes_share_storage_across_http_and_websocket() -> TestResult {
    let mut buffer = BytesMut::new();
    buffer.put_u16(0x1234);
    check(buffer.as_slice() == [0x12, 0x34], "put_u16 is big-endian").t()?;
    let frozen = buffer.freeze();
    check(frozen.as_slice() == [0x12, 0x34], "freeze keeps the bytes").t()?;
    let mut owned = Bytes::copy_from_slice(b"abcdef");
    let mid = owned.slice(2..4);
    let prefix = owned.split_to(2);
    let suffix = owned.split_off(0);
    check(prefix.as_slice() == b"ab", "split_to prefix").t()?;
    check(suffix.as_slice() == b"cdef", "split_off keeps the tail").t()?;
    check(mid.as_slice() == b"cd", "slice shares the middle").t()?;
    check(
        shared_pointer(prefix.as_slice(), mid.as_slice(), 2),
        "slice and split share storage",
    )
    .t()?;
    let shared = Bytes::copy_from_slice(b"ping");
    let request = Request::get("http://127.0.0.1/x")
        .map_err(show)
        .t()?
        .with_body(shared.clone());
    let mut http = BytesMut::new();
    Http1ClientCodec::default()
        .encode_request(&request, &mut http)
        .map_err(show)
        .t()?;
    check(
        http.as_slice().windows(4).any(|window| window == b"ping"),
        "http encoder accepts the shared body",
    )
    .t()?;
    let mut websocket = BytesMut::new();
    WebSocketCodec::client_default()
        .encode_message(&WebSocketMessage::Binary(shared), &mut websocket)
        .map_err(show)
        .t()?;
    check(
        !websocket.is_empty(),
        "websocket encoder accepts the shared body",
    )
}

fn handshake(client: &mut TlsSession, server: &mut TlsSession) -> TestResult {
    for _ in 0..64 {
        let mut wire = BytesMut::new();
        let sent = client.take_ciphertext(&mut wire).map_err(show).t()?;
        if sent > 0 {
            server.feed_ciphertext(wire.as_slice()).map_err(show).t()?;
        }
        wire.clear();
        let received = server.take_ciphertext(&mut wire).map_err(show).t()?;
        if received > 0 {
            client.feed_ciphertext(wire.as_slice()).map_err(show).t()?;
        }
        if sent + received == 0 && !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err(String::from("tls handshake did not finish"))
}

#[test]
fn it_02_tls_alpn_custom_ca_and_rejection() -> TestResult {
    let both = [AlpnProtocol::Http2, AlpnProtocol::Http11];
    let identity = support::localhost_identity(&both).t()?;
    let mut client = TlsSession::new_client(&identity.client, "localhost")
        .map_err(show)
        .t()?;
    let mut server = TlsSession::new_server(&identity.server).map_err(show).t()?;
    handshake(&mut client, &mut server).t()?;
    check(
        client.alpn_protocol() == Some(AlpnProtocol::Http2),
        "client prefers h2",
    )
    .t()?;
    check(
        server.alpn_protocol() == Some(AlpnProtocol::Http2),
        "server selects h2",
    )
    .t()?;
    let only_http1 = identity.client.clone().with_alpn(&[AlpnProtocol::Http11]);
    let mut client = TlsSession::new_client(&only_http1, "localhost").t()?;
    let mut server = TlsSession::new_server(&identity.server).t()?;
    handshake(&mut client, &mut server).t()?;
    check(
        client.alpn_protocol() == Some(AlpnProtocol::Http11)
            && server.alpn_protocol() == Some(AlpnProtocol::Http11),
        "overridden ALPN retains trust and restricts both peers to HTTP/1.1",
    )
    .t()?;

    let http_only = support::localhost_identity(&[AlpnProtocol::Http11]).t()?;
    let fallback =
        TlsClientConfig::with_root_certificates(std::slice::from_ref(&http_only.cert_der), &both)
            .map_err(show)
            .t()?;
    let mut client = TlsSession::new_client(&fallback, "localhost")
        .map_err(show)
        .t()?;
    let mut server = TlsSession::new_server(&http_only.server)
        .map_err(show)
        .t()?;
    handshake(&mut client, &mut server).t()?;
    check(
        client.alpn_protocol() == Some(AlpnProtocol::Http11),
        "client falls back to http/1.1",
    )
    .t()?;

    let http2_only = TlsClientConfig::with_root_certificates(
        std::slice::from_ref(&http_only.cert_der),
        &[AlpnProtocol::Http2],
    )
    .map_err(show)
    .t()?;
    let mut client = TlsSession::new_client(&http2_only, "localhost")
        .map_err(show)
        .t()?;
    let mut server = TlsSession::new_server(&http_only.server)
        .map_err(show)
        .t()?;
    check(
        handshake(&mut client, &mut server).is_err(),
        "alpn mismatch fails the handshake",
    )
    .t()?;

    let other = support::localhost_identity(&both).t()?;
    let foreign = TlsClientConfig::with_root_certificates(&[other.cert_der], &both)
        .map_err(show)
        .t()?;
    let mut client = TlsSession::new_client(&foreign, "localhost")
        .map_err(show)
        .t()?;
    let mut server = TlsSession::new_server(&identity.server).map_err(show).t()?;
    let untrusted = handshake(&mut client, &mut server);
    check(untrusted.is_err(), "untrusted certificate is rejected").t()?;

    let mut client = TlsSession::new_client(&identity.client, "example.invalid")
        .map_err(show)
        .t()?;
    let mut server = TlsSession::new_server(&identity.server).map_err(show).t()?;
    let wrong_name = handshake(&mut client, &mut server);
    check(wrong_name.is_err(), "wrong server name is rejected").t()?;
    check(
        TlsServerConfig::from_der_with_client_auth(Vec::new(), Vec::new(), &[], &both).is_err(),
        "empty mutual tls identity is rejected",
    )
    .t()?;
    Ok(())
}

fn read_response(
    raw: &[u8],
    config: Http1ClientConfig,
) -> std::result::Result<(Response, Http1KeepAlive, BytesMut), String> {
    let mut codec = Http1ClientCodec::new(config);
    let mut buf = BytesMut::new();
    buf.extend_from_slice(raw);
    let Some((response, keep_alive)) = codec
        .decode_response(&mut buf, Method::Get)
        .map_err(show)
        .t()?
    else {
        return Err(String::from("http/1 response did not complete"));
    };
    Ok((response, keep_alive, buf))
}

#[test]
fn it_03_http1_framing_limits_and_upgrade_trail() -> TestResult {
    let config = Http1ClientConfig {
        max_header_list_size: 1024,
        max_body_size: 32,
        ..Http1ClientConfig::default()
    };
    let (response, keep, _) =
        read_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", config).t()?;
    check(response.body.as_slice() == b"abc", "content-length body").t()?;
    check(
        keep == Http1KeepAlive::KeepAlive,
        "content-length keeps the connection",
    )
    .t()?;

    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nx-trail: 1\r\n\r\n";
    let (response, _, _) = read_response(chunked, config).t()?;
    check(
        response.body.as_slice() == b"hello",
        "chunk extension and trailer",
    )
    .t()?;

    let limited = Http1ClientConfig {
        max_header_list_size: 1024,
        max_body_size: 4,
        ..Http1ClientConfig::default()
    };
    let oversized = read_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345",
        limited,
    );
    check(
        matches!(oversized, Err(ref text) if text.contains("body size")),
        "max body is enforced",
    )
    .t()?;

    let upgrade = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nTRAIL";
    let (response, keep, rest) = read_response(upgrade, config).t()?;
    check(
        response.status == StatusCode::SWITCHING_PROTOCOLS,
        "101 status",
    )
    .t()?;
    check(keep == Http1KeepAlive::Upgrade, "101 is an upgrade").t()?;
    check(
        rest.as_slice() == b"TRAIL",
        "bytes after the upgrade header stay in the buffer",
    )
}

fn round_trip(frame: &Http2Frame) -> TestResult {
    let mut wire = BytesMut::new();
    encode_frame(frame, &mut wire).map_err(show).t()?;
    let decoded = decode_frame(&mut wire, DEFAULT_MAX_FRAME_SIZE)
        .map_err(show)
        .t()?
        .ok_or_else(|| String::from("frame did not decode"))
        .t()?;
    check(decoded == *frame, "frame round trip").t()?;
    check(wire.is_empty(), "frame consumed the buffer")
}

fn settle(client: &mut Http2Connection, server: &mut Http2Connection) -> TestResult {
    for _ in 0..16 {
        let mut forward = BytesMut::new();
        client.take_tx_bytes(&mut forward);
        if !forward.is_empty() {
            server.feed_bytes(&mut forward).map_err(show).t()?;
            check(forward.is_empty(), "server consumed client bytes").t()?;
        }
        let mut back = BytesMut::new();
        server.take_tx_bytes(&mut back);
        if !back.is_empty() {
            client.feed_bytes(&mut back).map_err(show).t()?;
            check(back.is_empty(), "client consumed server bytes").t()?;
        }
        if !client.has_tx_bytes() && !server.has_tx_bytes() {
            return Ok(());
        }
    }
    Err(String::from("http2 peers did not settle"))
}

#[test]
fn it_04_http2_frames_hpack_huffman_and_windows() -> TestResult {
    let block = Bytes::copy_from_slice(&[0x82]);
    round_trip(&Http2Frame::Data {
        stream_id: 1,
        end_stream: true,
        data: Bytes::copy_from_slice(b"hi"),
    })
    .t()?;
    round_trip(&Http2Frame::Headers {
        stream_id: 1,
        end_stream: false,
        end_headers: true,
        header_block: block,
    })
    .t()?;
    round_trip(&Http2Frame::Priority {
        stream_id: 1,
        exclusive: false,
        stream_dependency: 0,
        weight: 15,
    })
    .t()?;
    round_trip(&Http2Frame::RstStream {
        stream_id: 1,
        error_code: Http2ErrorCode::Cancel,
    })
    .t()?;
    let settings = Http2Settings {
        enable_push: false,
        ..Http2Settings::default()
    };
    round_trip(&Http2Frame::Settings {
        ack: false,
        settings,
    })
    .t()?;
    round_trip(&Http2Frame::Ping {
        ack: false,
        opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
    })
    .t()?;
    round_trip(&Http2Frame::GoAway {
        last_stream_id: 1,
        error_code: Http2ErrorCode::NoError,
        debug_data: Bytes::new(),
    })
    .t()?;
    round_trip(&Http2Frame::WindowUpdate {
        stream_id: 0,
        increment: 1,
    })
    .t()?;
    round_trip(&Http2Frame::Continuation {
        stream_id: 1,
        end_headers: true,
        header_block: Bytes::copy_from_slice(&[0x82]),
    })
    .t()?;

    let raw = [0, 0, 4, 5, 0, 0, 0, 0, 1, 0, 0, 0, 2];
    let mut promised = BytesMut::new();
    promised.extend_from_slice(&raw);
    let frame = decode_frame(&mut promised, DEFAULT_MAX_FRAME_SIZE)
        .map_err(show)
        .t()?
        .ok_or_else(|| String::from("push promise did not decode"))
        .t()?;
    check(
        matches!(frame, Http2Frame::Unknown { header, .. } if header.frame_type == Http2FrameType::PushPromise),
        "push promise decodes as an unknown frame",
    ).t()?;

    let decoded = HpackDecoder::new(4096, 8192)
        .decode(&[0x82])
        .map_err(show)
        .t()?;
    check(
        decoded == vec![(String::from(":method"), String::from("GET"))],
        "static index 2 is GET",
    )
    .t()?;
    let mut encoder = HpackEncoder::new(4096);
    encoder.set_max_table_size(0);
    let mut encoded = BytesMut::new();
    encoder.encode(
        &[
            (String::from("x-a"), String::from("one")),
            (String::from("x-b"), String::from("two")),
        ],
        &mut encoded,
    );
    let fields = HpackDecoder::new(4096, 8192)
        .decode(encoded.as_slice())
        .map_err(show)
        .t()?;
    check(
        fields.len() == 2,
        "dynamic table size update still decodes literals",
    )
    .t()?;
    let mut huff = BytesMut::new();
    huffman_encode(b"www.example.com", &mut huff);
    check(
        huffman_decode(huff.as_slice())
            .map_err(show)
            .t()?
            .as_slice()
            == b"www.example.com",
        "huffman round trip",
    )
    .t()?;
    check(
        huffman_encoded_len(b"www.example.com") == huff.len(),
        "huffman length matches",
    )
    .t()?;

    let too_wide = Http2Settings {
        initial_window_size: 0x8000_0000,
        ..Http2Settings::default()
    };
    let mut wire = BytesMut::new();
    let window_error = encode_frame(
        &Http2Frame::Settings {
            ack: false,
            settings: too_wide,
        },
        &mut wire,
    );
    check(
        matches!(
            window_error,
            Err(ProtoError::Http2ConnectionError {
                code: Http2ErrorCode::FlowControlError,
                ..
            })
        ),
        "initial window above 2^31-1 is rejected",
    )
    .t()?;
    let tiny = Http2Settings {
        max_frame_size: 16_383,
        ..Http2Settings::default()
    };
    let frame_error = encode_frame(
        &Http2Frame::Settings {
            ack: false,
            settings: tiny,
        },
        &mut wire,
    );
    check(
        frame_error.is_err(),
        "max frame size below 16384 is rejected",
    )
    .t()?;

    let mut client = Http2Connection::client_default();
    let mut server = Http2Connection::server_default();
    settle(&mut client, &mut server).t()?;
    let request = Request::post("https://localhost/w", vec![7u8; 100])
        .map_err(show)
        .t()?;
    let stream = client.submit_request(&request).map_err(show).t()?;
    let shrink = Http2Settings {
        enable_push: false,
        initial_window_size: 0,
        ..Http2Settings::default()
    };
    let mut update = BytesMut::new();
    encode_frame(
        &Http2Frame::Settings {
            ack: false,
            settings: shrink,
        },
        &mut update,
    )
    .map_err(show)
    .t()?;
    client.feed_bytes(&mut update).map_err(show).t()?;
    let window = client
        .stream_send_window(stream)
        .ok_or_else(|| String::from("missing stream window"))
        .t()?;
    check(
        window < 0,
        "settings delta drives the stream window negative",
    )
}

#[test]
fn it_05_websocket_accept_mask_continuation_and_utf8() -> TestResult {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    check(
        WebSocketHandshake::compute_accept_key(key) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "rfc accept key",
    )
    .t()?;
    let mut client = WebSocketCodec::client_default();
    let mut server = WebSocketCodec::server_default();
    let mut wire = BytesMut::new();
    client
        .encode_frame(
            &WebSocketFrame {
                fin: false,
                opcode: WebSocketOpcode::Text,
                payload: Bytes::copy_from_slice(b"hel"),
            },
            &mut wire,
        )
        .map_err(show)
        .t()?;
    client
        .encode_message(
            &WebSocketMessage::Ping(Bytes::copy_from_slice(b"p")),
            &mut wire,
        )
        .map_err(show)
        .t()?;
    client
        .encode_frame(
            &WebSocketFrame {
                fin: true,
                opcode: WebSocketOpcode::Continuation,
                payload: Bytes::copy_from_slice(b"lo"),
            },
            &mut wire,
        )
        .map_err(show)
        .t()?;
    let first = server.decode_message(&mut wire).map_err(show).t()?;
    check(
        matches!(first, Some(WebSocketMessage::Ping(payload)) if payload.as_slice() == b"p"),
        "ping is delivered between fragments",
    )
    .t()?;
    let text = server.decode_message(&mut wire).map_err(show).t()?;
    check(
        matches!(text, Some(WebSocketMessage::Text(value)) if value == "hello"),
        "continuation reassembles text",
    )
    .t()?;
    let mut bare = BytesMut::new();
    bare.extend_from_slice(b"\x81\x01A");
    let masked = server.decode_message(&mut bare);
    check(
        matches!(masked, Err(ProtoError::WebSocketProtocol(ref text)) if text.contains("incorrect masking")),
        "unmasked client frame is rejected",
    ).t()?;
    let mut bad = BytesMut::new();
    let encoded = client.encode_frame(
        &WebSocketFrame {
            fin: true,
            opcode: WebSocketOpcode::Text,
            payload: Bytes::copy_from_slice(&[0xff]),
        },
        &mut bad,
    );
    check(
        matches!(encoded, Err(ProtoError::InvalidUtf8(_))),
        "invalid text is InvalidUtf8",
    )
}

#[derive(HeaderMap)]
struct ProbeHeaders {
    #[header(name = "x-count")]
    count: u16,
    #[header(name = "x-trace")]
    trace: Option<String>,
}

#[derive(RestRequest)]
#[rest(method = "PUT", path = "/items/{id}")]
struct ProbeUpdate<'a> {
    #[path_param]
    id: &'a str,
    #[query]
    limit: Option<usize>,
    #[header(name = "x-token")]
    token: Option<&'a str>,
    #[body]
    body: &'a [u8],
}

struct MacroGate;

#[http_service]
impl MacroGate {
    #[get("/ping")]
    fn ping(&mut self, _ctx: &mut RequestContext, _req: Request) -> nexora::Result<Response> {
        Ok(Response::text(StatusCode::OK, "pong"))
    }

    #[post("/hold")]
    fn hold(
        &mut self,
        _ctx: &mut RequestContext,
        _req: Request,
        responder: nexora::Responder,
    ) -> nexora::Result<()> {
        responder.respond(Response::text(StatusCode::OK, "held"))
    }
}

#[test]
fn it_06_macros_headers_rest_and_routes() -> TestResult {
    let values = headers! { "x-count" => "4", "x-trace" => "span" };
    let parsed = ProbeHeaders::from_headers(&values).map_err(show).t()?;
    check(parsed.count == 4, "header map integer").t()?;
    check(parsed.trace.as_deref() == Some("span"), "optional header").t()?;
    let _fields = http2_headers! { ":method" => "PUT", "x-count" => "4" };
    let update = ProbeUpdate {
        id: "9",
        limit: Some(2),
        token: Some("tok"),
        body: b"abc",
    };
    let request = update.into_request("http://127.0.0.1").map_err(show).t()?;
    check(request.path() == "/items/9", "rest path parameter").t()?;
    check(request.header("x-token") == Some("tok"), "rest header").t()?;
    let gate = support::Gate::new(support::GateMode::Echo);
    let hits = gate.hits();
    let _service = MacroGate;
    check(hits.get() == 0, "gate starts idle").t()?;
    let mut ring = proactor().t()?;
    let mut server = nexora::HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        support::server_config(3).t()?,
        gate,
    )
    .t()?;
    let port = server.local_addr().port();
    let mut client = nexora::HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let slot = support::Slot::new();
    let done = slot.clone();
    let request = Request::get(&format!("http://127.0.0.1:{port}/item/9")).t()?;
    client
        .submit(&mut ring, request, move |_ctx, _id, result| {
            done.set(result);
        })
        .t()?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(slot.calls() > 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(finished, "item route did not finish").t()?;
    let response = slot
        .take()
        .ok_or_else(|| String::from("missing item response"))?
        .t()?;
    check(hits.get() == 1, "item route ran").t()?;
    check(response.body.as_slice() == b"9", "item id is the path tail")
}

#[test]
fn it_08_http1_body_limit_returns_413() -> TestResult {
    let mut ring = proactor().t()?;
    let mut config = support::server_config(3).t()?;
    config.max_body_size = 8;
    let mut server = nexora::HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        config,
        support::Gate::new(support::GateMode::Echo),
    )
    .t()?;
    let port = server.local_addr().port();
    let mut client = nexora::HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let slot = support::Slot::new();
    let done = slot.clone();
    let request = Request::post(
        &format!("http://127.0.0.1:{port}/echo"),
        Bytes::copy_from_slice(&[7u8; 16]),
    )
    .t()?;
    client
        .submit(&mut ring, request, move |_ctx, _id, result| {
            done.set(result);
        })
        .t()?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(slot.calls() > 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(finished, "413 request did not finish").t()?;
    let response = slot
        .take()
        .ok_or_else(|| String::from("missing 413"))?
        .t()?;
    check(
        response.status == StatusCode::PAYLOAD_TOO_LARGE,
        "oversized body is 413",
    )
}

#[test]
fn it_07_static_pin_skips_dns_and_named_host_queries_mock() -> TestResult {
    let dns = MockDns::spawn(DnsPlan::answer(vec![Ipv4Addr::LOCALHOST]))
        .map_err(show)
        .t()?;
    let mut ring = proactor().t()?;
    let mut pinned_config = client_config(1, 2).t()?;
    pinned_config.dns_servers_csv = Some(dns.servers_csv());
    let mut pinned = nexora::HttpClient::new(&mut ring, pinned_config).t()?;
    pinned.resolve_host("pinned.test", 9, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let pinned_slot = support::Slot::new();
    let pinned_done = pinned_slot.clone();
    let pinned_request = Request::get("http://pinned.test:9/echo")
        .map_err(show)
        .t()?;
    pinned
        .submit(&mut ring, pinned_request, move |_ctx, _id, result| {
            pinned_done.set(result.is_err());
        })
        .map_err(show)
        .t()?;
    let pinned_done_drive = drive_until(
        &mut ring,
        |ring| {
            pinned.drive(ring)?;
            Ok(pinned_slot.calls() > 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(pinned_done_drive, "pinned request did not finish").t()?;
    check(pinned_slot.calls() == 1, "pinned callback ran once").t()?;
    check(
        dns.udp_queries() == 0,
        "static pin skipped the mock resolver",
    )
    .t()?;
    pinned.shutdown(&mut ring);
    let mut named_config = client_config(4, 5).t()?;
    named_config.dns_servers_csv = Some(dns.servers_csv());
    let mut named = nexora::HttpClient::new(&mut ring, named_config).t()?;
    let named_slot = support::Slot::new();
    let named_done = named_slot.clone();
    let named_request = Request::get("http://live.test:9/echo").map_err(show).t()?;
    named
        .submit(&mut ring, named_request, move |_ctx, _id, result| {
            named_done.set(result.is_err());
        })
        .map_err(show)
        .t()?;
    let named_done_drive = drive_until(
        &mut ring,
        |ring| {
            named.drive(ring)?;
            Ok(named_slot.calls() > 0 && dns.udp_queries() > 0)
        },
        Duration::from_secs(3),
    )
    .t()?;
    check(named_done_drive, "named host did not finish").t()?;
    check(named_slot.calls() == 1, "named callback ran once").t()?;
    check(
        dns.udp_queries() >= 1,
        "named host queried the mock resolver",
    )
    .t()?;
    Ok(())
}
