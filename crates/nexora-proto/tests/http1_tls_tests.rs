//! Protocol loops run in memory; the transport and application dispatcher are controlled peers.

use nexora_proto::{
    AlpnProtocol, Bytes, BytesMut, Headers, Http1ClientCodec, Http1ClientConfig, Http1KeepAlive,
    Http1ServerCodec, Http1ServerConfig, Method, ProtoError, Request, Response, Result, StatusCode,
    TlsClientConfig, TlsServerConfig, TlsSession, Uri, Version, WebSocketCodec, WebSocketFrame,
    WebSocketHandshake, WebSocketMessage, WebSocketOpcode,
};

fn buffer(data: &[u8]) -> BytesMut {
    let mut result = BytesMut::new();
    result.extend_from_slice(data);
    result
}

fn complete<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => panic!("expected a complete protocol message"),
    }
}

fn rejected<T>(result: Result<T>) {
    assert!(result.is_err());
}

fn assert_tls_error<T>(result: Result<T>) {
    assert!(matches!(result, Err(ProtoError::Tls(_))));
}

fn reject_wire(input: &mut BytesMut, is_request: bool) {
    let before = input.clone();
    if is_request {
        rejected(Http1ServerCodec::default().decode_request(input));
    } else {
        rejected(Http1ClientCodec::default().decode_response(input, Method::Get));
    }
    assert_eq!(*input, before);
}

fn transfer(source: &mut TlsSession, target: &mut TlsSession, fragment: usize) -> Result<usize> {
    let mut wire = BytesMut::new();
    let count = source.take_ciphertext(&mut wire)?;
    assert_eq!(count, wire.len());
    for chunk in wire.chunks(fragment) {
        target.feed_ciphertext(chunk)?;
    }
    Ok(count)
}

fn pump(client: &mut TlsSession, server: &mut TlsSession, fragment: usize) -> Result<()> {
    for _ in 0..64 {
        let sent = transfer(client, server, fragment)?;
        let received = transfer(server, client, fragment)?;
        if sent + received == 0 {
            return Ok(());
        }
    }
    panic!("TLS peers failed to reach an idle transport boundary");
}

fn connect(
    client_config: &TlsClientConfig,
    server_config: &TlsServerConfig,
    server_name: &str,
    fragment: usize,
) -> Result<(TlsSession, TlsSession)> {
    let mut client = TlsSession::new_client(client_config, server_name)?;
    let mut server = TlsSession::new_server(server_config)?;
    assert!(client.is_handshaking());
    assert!(server.is_handshaking());
    pump(&mut client, &mut server, fragment)?;
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    Ok((client, server))
}

fn trusted_pair(fragment: usize) -> Result<(TlsSession, TlsSession)> {
    let alpn = [AlpnProtocol::Http11];
    let (server, certificate) = TlsServerConfig::self_signed_for_localhost(&alpn)?;
    let client = TlsClientConfig::with_root_certificates(&[certificate], &alpn)?;
    connect(&client, &server, "localhost", fragment)
}

fn send(
    source: &mut TlsSession,
    target: &mut TlsSession,
    data: &[u8],
    fragment: usize,
) -> Result<BytesMut> {
    let mut offset = 0;
    let mut output = BytesMut::new();
    while offset < data.len() {
        let written = source.write_plaintext(&data[offset..])?;
        assert!(
            written > 0,
            "application writes must make progress after draining"
        );
        assert!(written <= data.len() - offset);
        offset += written;
        pump(source, target, fragment)?;
        target.read_plaintext(&mut output)?;
    }
    pump(source, target, fragment)?;
    target.read_plaintext(&mut output)?;
    assert_eq!(output.as_ref(), data);
    Ok(output)
}

mod integration_tests {
    use super::*;

    #[test]
    fn content_length_request_and_response_preserve_following_messages() -> Result<()> {
        let mut client = Http1ClientCodec::default();
        let mut server = Http1ServerCodec::default();
        let request = Request::post("https://localhost/items?limit=2", "abc")?;
        let mut wire = BytesMut::new();
        client.encode_request(&request, &mut wire)?;
        wire.extend_from_slice(b"GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (decoded, keep_alive) = complete(server.decode_request(&mut wire)?);
        assert_eq!(decoded.method, Method::Post);
        assert_eq!(decoded.path(), "/items");
        assert_eq!(decoded.uri.query(), Some("limit=2"));
        assert_eq!(decoded.header("host"), Some("localhost"));
        assert_eq!(decoded.body.as_ref(), b"abc");
        assert_eq!(keep_alive, Http1KeepAlive::KeepAlive);
        assert_eq!(
            complete(server.decode_request(&mut wire)?).0.path(),
            "/next"
        );
        assert!(wire.is_empty());

        let mut responses = BytesMut::new();
        server.encode_response(&Response::ok("first"), &mut responses)?;
        server.encode_response(&Response::ok("second"), &mut responses)?;
        for body in [b"first".as_slice(), b"second".as_slice()] {
            let (response, keep_alive) =
                complete(client.decode_response(&mut responses, Method::Get)?);
            assert_eq!(response.body.as_ref(), body);
            assert_eq!(keep_alive, Http1KeepAlive::KeepAlive);
        }
        assert!(responses.is_empty());
        Ok(())
    }

    #[test]
    fn chunk_extensions_and_trailers_reassemble_in_both_directions() -> Result<()> {
        let body =
            b"4;name=value\r\nWiki\r\n5;other=\"x\"\r\npedia\r\n0\r\nX-Checksum: yes\r\n\r\n";
        let mut request =
            buffer(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n");
        request.extend_from_slice(body);
        let decoded = complete(Http1ServerCodec::default().decode_request(&mut request)?).0;
        assert_eq!(decoded.body.as_ref(), b"Wikipedia");
        assert!(request.is_empty());
        let mut response = buffer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        response.extend_from_slice(body);
        let decoded =
            complete(Http1ClientCodec::default().decode_response(&mut response, Method::Get)?).0;
        assert_eq!(decoded.body.as_ref(), b"Wikipedia");
        assert!(response.is_empty());
        Ok(())
    }

    #[test]
    fn generated_chunked_messages_round_trip_empty_and_nonempty_bodies() -> Result<()> {
        for body in ["", "chunk payload"] {
            let mut client = Http1ClientCodec::default();
            let mut server = Http1ServerCodec::default();
            let request = Request::post("http://localhost/", body)?
                .with_header("transfer-encoding", "chunked");
            let mut wire = BytesMut::new();
            client.encode_request(&request, &mut wire)?;
            assert_eq!(
                complete(server.decode_request(&mut wire)?).0.body.as_ref(),
                body.as_bytes()
            );
            assert!(wire.is_empty());
            let response = Response::ok(body).with_header("transfer-encoding", "chunked");
            server.encode_response(&response, &mut wire)?;
            assert_eq!(
                complete(client.decode_response(&mut wire, Method::Post)?)
                    .0
                    .body
                    .as_ref(),
                body.as_bytes()
            );
            assert!(wire.is_empty());
        }
        Ok(())
    }

    #[test]
    fn head_and_no_content_responses_stop_at_headers() -> Result<()> {
        let mut client = Http1ClientCodec::default();
        for (method, head) in [
            (
                Method::Head,
                b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n".as_slice(),
            ),
            (Method::Get, b"HTTP/1.1 204 No Content\r\n\r\n".as_slice()),
        ] {
            let mut wire = buffer(head);
            wire.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            assert!(
                complete(client.decode_response(&mut wire, method)?)
                    .0
                    .body
                    .is_empty()
            );
            assert_eq!(
                complete(client.decode_response(&mut wire, Method::Get)?)
                    .0
                    .body
                    .as_ref(),
                b"ok"
            );
            assert!(wire.is_empty());
        }
        Ok(())
    }

    #[test]
    fn alpn_prefers_server_http2_and_falls_back_to_http11() -> Result<()> {
        for server_alpn in [
            vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
            vec![AlpnProtocol::Http11],
        ] {
            let (server, certificate) = TlsServerConfig::self_signed_for_localhost(&server_alpn)?;
            let client = TlsClientConfig::with_root_certificates(
                &[certificate],
                &[AlpnProtocol::Http11, AlpnProtocol::Http2],
            )?;
            let (client, server) = connect(&client, &server, "localhost", 7)?;
            assert_eq!(client.alpn_protocol(), Some(server_alpn[0]));
            assert_eq!(server.alpn_protocol(), Some(server_alpn[0]));
        }
        Ok(())
    }

    #[test]
    fn insecure_client_permits_untrusted_local_certificate() -> Result<()> {
        let (server, _) = TlsServerConfig::self_signed_for_localhost(&[AlpnProtocol::Http11])?;
        let client = TlsClientConfig::insecure_client(&[AlpnProtocol::Http11])?;
        let (client, server) = connect(&client, &server, "untrusted.example", 13)?;
        assert_eq!(client.alpn_protocol(), Some(AlpnProtocol::Http11));
        assert_eq!(server.alpn_protocol(), Some(AlpnProtocol::Http11));
        Ok(())
    }
}

mod e2e_tests {
    use super::*;

    #[test]
    fn in_memory_https_get_and_post_reuse_one_tls_session() -> Result<()> {
        let (mut client_tls, mut server_tls) = trusted_pair(3)?;
        let mut client = Http1ClientCodec::default();
        let mut server = Http1ServerCodec::default();
        for request in [
            Request::get("https://localhost/health")?,
            Request::post("https://localhost/echo", "{\"value\":7}")?,
        ] {
            let mut wire = BytesMut::new();
            client.encode_request(&request, &mut wire)?;
            let mut incoming = send(&mut client_tls, &mut server_tls, wire.as_ref(), 5)?;
            let (decoded, keep_alive) = complete(server.decode_request(&mut incoming)?);
            assert_eq!(decoded.method, request.method);
            assert_eq!(decoded.body, request.body);
            assert_eq!(keep_alive, Http1KeepAlive::KeepAlive);
            assert!(incoming.is_empty());
            let body = if decoded.method == Method::Get {
                Bytes::from("healthy")
            } else {
                decoded.body
            };
            let response = Response::ok(body).with_header("transfer-encoding", "chunked");
            wire.clear();
            server.encode_response(&response, &mut wire)?;
            let mut incoming = send(&mut server_tls, &mut client_tls, wire.as_ref(), 2)?;
            let (decoded, keep_alive) =
                complete(client.decode_response(&mut incoming, request.method)?);
            assert_eq!(decoded.status, StatusCode::OK);
            assert_eq!(decoded.body, response.body);
            assert_eq!(keep_alive, Http1KeepAlive::KeepAlive);
            assert!(incoming.is_empty());
        }
        Ok(())
    }

    #[test]
    fn in_memory_wss_upgrade_preserves_duplex_frames_and_fragmented_message() -> Result<()> {
        let (mut client_tls, mut server_tls) = trusted_pair(11)?;
        let mut http_client = Http1ClientCodec::default();
        let mut http_server = Http1ServerCodec::default();
        let mut websocket_client = WebSocketCodec::client_default();
        let mut websocket_server = WebSocketCodec::server_default();
        let key = WebSocketHandshake::generate_key(41);
        let request = WebSocketHandshake::build_upgrade_request(
            &Uri::parse("wss://localhost/stream")?,
            &key,
            &Headers::new(),
        );
        let mut wire = BytesMut::new();
        http_client.encode_request(&request, &mut wire)?;
        let greeting = WebSocketMessage::Text("first client frame".into());
        websocket_client.encode_message(&greeting, &mut wire)?;
        let mut input = send(&mut client_tls, &mut server_tls, wire.as_ref(), 1)?;
        let (request, state) = complete(http_server.decode_request(&mut input)?);
        assert_eq!(state, Http1KeepAlive::Upgrade);
        assert_eq!(WebSocketHandshake::validate_upgrade_request(&request)?, key);
        assert_eq!(websocket_server.decode_message(&mut input)?, Some(greeting));
        assert!(input.is_empty());

        wire.clear();
        http_server
            .encode_response(&WebSocketHandshake::build_upgrade_response(&key), &mut wire)?;
        let binary = WebSocketMessage::Binary(Bytes::from_static(b"\x00\xff\x01"));
        websocket_server.encode_message(&binary, &mut wire)?;
        let mut input = send(&mut server_tls, &mut client_tls, wire.as_ref(), 1)?;
        let (response, state) = complete(http_client.decode_response(&mut input, Method::Get)?);
        assert_eq!(state, Http1KeepAlive::Upgrade);
        WebSocketHandshake::validate_upgrade_response(&response, &key)?;
        assert_eq!(websocket_client.decode_message(&mut input)?, Some(binary));
        assert!(input.is_empty());

        let large = vec![b'x'; 65_536];
        wire.clear();
        for (index, part) in large.chunks(16_384).enumerate() {
            websocket_client.encode_frame(
                &WebSocketFrame {
                    fin: index == 3,
                    opcode: if index == 0 {
                        WebSocketOpcode::Binary
                    } else {
                        WebSocketOpcode::Continuation
                    },
                    payload: Bytes::copy_from_slice(part),
                },
                &mut wire,
            )?;
            if index == 1 {
                websocket_client
                    .encode_message(&WebSocketMessage::Ping(Bytes::from("probe")), &mut wire)?;
            }
        }
        let mut input = send(&mut client_tls, &mut server_tls, wire.as_ref(), 17)?;
        assert_eq!(
            websocket_server.decode_message(&mut input)?,
            Some(WebSocketMessage::Ping(Bytes::from("probe")))
        );
        assert_eq!(
            websocket_server.decode_message(&mut input)?,
            Some(WebSocketMessage::Binary(Bytes::from(large)))
        );
        assert!(input.is_empty());
        wire.clear();
        let reply = WebSocketMessage::Text("received fragmented payload".into());
        websocket_server.encode_message(&reply, &mut wire)?;
        let mut input = send(&mut server_tls, &mut client_tls, wire.as_ref(), 1)?;
        assert_eq!(websocket_client.decode_message(&mut input)?, Some(reply));
        Ok(())
    }
}

mod lifecycle_tests {
    use super::*;

    #[test]
    fn http10_and_http11_keep_alive_and_close_follow_wire_policy() -> Result<()> {
        for (version, connection, expected) in [
            ("HTTP/1.0", "", Http1KeepAlive::Close),
            (
                "HTTP/1.0",
                "Connection: keep-alive\r\n",
                Http1KeepAlive::KeepAlive,
            ),
            ("HTTP/1.1", "", Http1KeepAlive::KeepAlive),
            (
                "HTTP/1.1",
                "Connection: \u{a0}close\r\n",
                Http1KeepAlive::KeepAlive,
            ),
            ("HTTP/1.1", "Connection: close\r\n", Http1KeepAlive::Close),
        ] {
            let mut wire = buffer(
                format!("GET / HTTP/1.1\r\nHost: localhost\r\n{connection}\r\n")
                    .replace("HTTP/1.1", version)
                    .as_bytes(),
            );
            let mut server = Http1ServerCodec::default();
            assert_eq!(complete(server.decode_request(&mut wire)?).1, expected);
            let mut wire = buffer(
                format!("{version} 200 OK\r\nContent-Length: 0\r\n{connection}\r\n").as_bytes(),
            );
            assert_eq!(
                complete(Http1ClientCodec::default().decode_response(&mut wire, Method::Get)?).1,
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn close_and_upgrade_disable_codec_reuse_without_consuming_trailing_bytes() -> Result<()> {
        for (status, expected) in [
            (StatusCode::OK, Http1KeepAlive::Close),
            (StatusCode::SWITCHING_PROTOCOLS, Http1KeepAlive::Upgrade),
        ] {
            let mut server = Http1ServerCodec::default();
            let mut client = Http1ClientCodec::default();
            let response = Response::new(status).with_header("connection", "close");
            let mut wire = BytesMut::new();
            server.encode_response(&response, &mut wire)?;
            wire.extend_from_slice(b"trailing");
            let (_, keep_alive) = complete(client.decode_response(&mut wire, Method::Get)?);
            assert_eq!(keep_alive, expected);
            rejected(client.decode_response(&mut wire, Method::Get));
            assert_eq!(wire.as_ref(), b"trailing");
            rejected(client.encode_request(&Request::get("http://localhost/")?, &mut wire));
            rejected(server.encode_response(&response, &mut wire));
            rejected(server.decode_request(&mut wire));
            assert_eq!(wire.as_ref(), b"trailing");
        }
        Ok(())
    }

    #[test]
    fn close_notify_drains_plaintext_and_closes_both_read_directions() -> Result<()> {
        let (mut client, mut server) = trusted_pair(1)?;
        assert_eq!(client.write_plaintext(b"last message")?, 12);
        client.send_close_notify();
        pump(&mut client, &mut server, 1)?;
        let mut plain = BytesMut::new();
        assert_eq!(server.read_plaintext(&mut plain)?, 12);
        assert_eq!(plain.as_ref(), b"last message");
        assert_eq!(server.read_plaintext(&mut plain)?, 0);
        assert!(!server.wants_read());
        assert_tls_error(client.write_plaintext(b"too late"));
        send(&mut server, &mut client, b"final reply", 1)?;
        client.send_close_notify();
        assert!(!client.wants_write());
        server.send_close_notify();
        server.send_close_notify();
        pump(&mut client, &mut server, 1)?;
        assert_eq!(client.read_plaintext(&mut BytesMut::new())?, 0);
        assert!(!client.wants_read());
        assert!(!client.wants_write());
        assert!(!server.wants_write());
        assert_tls_error(server.write_plaintext(b"too late"));
        Ok(())
    }

    #[test]
    fn close_before_handshake_drains_queued_plaintext_then_eof() -> Result<()> {
        let alpn = [AlpnProtocol::Http11];
        let (config, cert) = TlsServerConfig::self_signed_for_localhost(&alpn)?;
        let policy = TlsClientConfig::with_root_certificates(&[cert], &alpn)?;
        let mut client = TlsSession::new_client(&policy, "localhost")?;
        let mut server = TlsSession::new_server(&config)?;
        assert_eq!(client.write_plaintext(b"queued")?, 6);
        client.send_close_notify();
        client.send_close_notify();
        assert_tls_error(client.write_plaintext(b"late"));
        pump(&mut client, &mut server, 1)?;
        assert!(!client.is_handshaking() && !server.is_handshaking());
        let mut plain = BytesMut::new();
        assert_eq!(server.read_plaintext(&mut plain)?, 6);
        assert_eq!(plain.as_ref(), b"queued");
        assert_eq!(server.read_plaintext(&mut plain)?, 0);
        assert!(!server.wants_read());
        Ok(())
    }

    #[test]
    fn ciphertext_after_close_preserves_final_plaintext_independent_of_batch_size() -> Result<()> {
        for trailing in [1, 131_073] {
            let (mut client, mut server) = trusted_pair(17)?;
            assert_eq!(client.write_plaintext(b"final")?, 5);
            client.send_close_notify();
            let mut wire = BytesMut::new();
            client.take_ciphertext(&mut wire)?;
            wire.resize(wire.len() + trailing, 0);
            assert_eq!(server.feed_ciphertext(wire.as_ref())?, 5);
            assert_eq!(server.feed_ciphertext(&[0])?, 5);
            let mut plain = BytesMut::new();
            assert_eq!(server.read_plaintext(&mut plain)?, 5);
            assert_eq!(plain.as_ref(), b"final");
            assert!(!server.wants_read());
            assert_eq!(
                send(&mut server, &mut client, b"reply", 1)?.as_ref(),
                b"reply"
            );
        }
        Ok(())
    }

    #[test]
    fn websocket_two_way_normal_close_round_trips_code_and_reason() -> Result<()> {
        let mut client = WebSocketCodec::client_default();
        let mut server = WebSocketCodec::server_default();
        let mut wire = BytesMut::new();
        let close = WebSocketMessage::Close(Some(nexora_proto::WebSocketCloseFrame {
            code: nexora_proto::WebSocketCloseCode::Normal,
            reason: "complete".into(),
        }));
        client.encode_message(&close, &mut wire)?;
        assert_eq!(server.decode_message(&mut wire)?, Some(close.clone()));
        assert!(wire.is_empty());
        server.encode_message(&close, &mut wire)?;
        assert_eq!(client.decode_message(&mut wire)?, Some(close));
        assert!(wire.is_empty());
        Ok(())
    }

    #[test]
    fn fatal_tls_record_failure_remains_terminal() -> Result<()> {
        let (_, mut server) = trusted_pair(13)?;
        assert_tls_error(server.feed_ciphertext(&[0; 8]));
        assert!(!server.wants_read());
        assert_tls_error(server.feed_ciphertext(&[]));
        assert_tls_error(server.read_plaintext(&mut BytesMut::new()));
        assert_tls_error(server.write_plaintext(b"rejected"));
        let mut alert = BytesMut::new();
        assert!(server.take_ciphertext(&mut alert)? > 0);
        assert!(!server.wants_write());
        Ok(())
    }
}

mod scenario_tests {
    use super::*;

    #[test]
    fn every_incomplete_chunked_prefix_is_retained_without_consumption() -> Result<()> {
        let request = b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-End: yes\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-End: yes\r\n\r\n";
        for (raw, is_request) in [(request.as_slice(), true), (response.as_slice(), false)] {
            let mut client = Http1ClientCodec::default();
            let mut server = Http1ServerCodec::default();
            let mut wire = BytesMut::new();
            for (index, byte) in raw.iter().enumerate() {
                wire.put_u8(*byte);
                let before = wire.clone();
                let result = if is_request {
                    server.decode_request(&mut wire)?.map(|value| value.0.body)
                } else {
                    client
                        .decode_response(&mut wire, Method::Get)?
                        .map(|value| value.0.body)
                };
                if index + 1 < raw.len() {
                    assert!(result.is_none());
                    assert_eq!(wire, before);
                } else {
                    assert_eq!(complete(result).as_ref(), b"abc");
                    assert!(wire.is_empty());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_version_and_unicode_transfer_codings_fail_atomically() -> Result<()> {
        for (version, coding) in [
            (Version::Http10, "chunked"),
            (Version::Http11, "\u{a0}chunked"),
        ] {
            let mut request =
                Request::post("http://localhost/", "x")?.with_header("transfer-encoding", coding);
            request.version = version;
            let mut response = Response::ok("x").with_header("transfer-encoding", coding);
            response.version = version;
            let mut out = buffer(b"prefix");
            rejected(Http1ClientCodec::default().encode_request(&request, &mut out));
            rejected(Http1ServerCodec::default().encode_response(&response, &mut out));
            assert_eq!(out.as_ref(), b"prefix");
            for (line, is_request) in [
                (
                    format!("POST / {}\r\nHost: localhost", version.as_str()),
                    true,
                ),
                (format!("{} 200 OK", version.as_str()), false),
            ] {
                let mut input = buffer(
                    format!("{line}\r\nTransfer-Encoding: {coding}\r\n\r\n1\r\nx\r\n0\r\n\r\n")
                        .as_bytes(),
                );
                reject_wire(&mut input, is_request);
            }
        }
        let mut input =
            buffer(b"CONNECT http://localhost:443/ HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let before = input.clone();
        rejected(Http1ServerCodec::default().decode_request(&mut input));
        assert_eq!(input, before);
        let mut input = buffer(b"GET HTTP://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(
            complete(Http1ServerCodec::default().decode_request(&mut input)?)
                .0
                .uri
                .host(),
            "localhost"
        );
        Ok(())
    }

    #[test]
    fn declared_body_limits_fail_before_body_bytes_arrive() {
        for framing in [
            "Content-Length: 5\r\n\r\n",
            "Transfer-Encoding: chunked\r\n\r\n5\r\n",
        ] {
            let mut request =
                buffer(format!("POST / HTTP/1.1\r\nHost: localhost\r\n{framing}").as_bytes());
            let before = request.clone();
            let mut server = Http1ServerCodec::new(Http1ServerConfig {
                max_body_size: 4,
                ..Default::default()
            });
            assert!(matches!(
                server.decode_request(&mut request),
                Err(ProtoError::BodyTooLarge { size: 5, max: 4 })
            ));
            assert_eq!(request, before);
            let mut response = buffer(format!("HTTP/1.1 200 OK\r\n{framing}").as_bytes());
            let before = response.clone();
            let mut client = Http1ClientCodec::new(Http1ClientConfig {
                max_body_size: 4,
                ..Default::default()
            });
            assert!(matches!(
                client.decode_response(&mut response, Method::Get),
                Err(ProtoError::BodyTooLarge { size: 5, max: 4 })
            ));
            assert_eq!(response, before);
        }
    }

    #[test]
    fn cumulative_chunks_and_incomplete_headers_respect_limits() {
        let mut server = Http1ServerCodec::new(Http1ServerConfig {
            max_body_size: 4,
            ..Default::default()
        });
        let mut wire = buffer(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\n");
        assert!(matches!(
            server.decode_request(&mut wire),
            Err(ProtoError::BodyTooLarge { size: 5, max: 4 })
        ));
        for suffix in ["", "\r\n\r\n"] {
            let oversized = format!("GET / HTTP/1.1\r\nX-Large: {}{suffix}", "x".repeat(100));
            let mut wire = buffer(oversized.as_bytes());
            let mut server = Http1ServerCodec::new(Http1ServerConfig {
                max_header_list_size: 64,
                ..Default::default()
            });
            assert!(matches!(
                server.decode_request(&mut wire),
                Err(ProtoError::HeaderListTooLarge { max: 64, .. })
            ));
            let oversized = format!("HTTP/1.1 200 OK\r\nX-Large: {}{suffix}", "x".repeat(100));
            let mut wire = buffer(oversized.as_bytes());
            let mut client = Http1ClientCodec::new(Http1ClientConfig {
                max_header_list_size: 64,
                ..Default::default()
            });
            assert!(matches!(
                client.decode_response(&mut wire, Method::Get),
                Err(ProtoError::HeaderListTooLarge { max: 64, .. })
            ));
        }
    }

    #[test]
    fn ambiguous_framing_and_forbidden_trailers_fail_without_consumption() {
        for framing in [
            "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "Content-Length: 1\r\nContent-Length: 2\r\n\r\nxx",
            "Transfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 7\r\n\r\n",
            "Transfer-Encoding: chunked\r\n\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "Transfer-Encoding: chunked\r\n\r\nxyz\r\n",
            "Upgrade: websocket\r\nContent-Length: 1\r\n\r\nx",
            "Upgrade: websocket\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "Transfer-Encoding: chunked\r\n\r\nffffffffffffffffffffffffffffffff\r\n",
        ] {
            let mut wire =
                buffer(format!("POST / HTTP/1.1\r\nHost: localhost\r\n{framing}").as_bytes());
            reject_wire(&mut wire, true);
            if !framing.starts_with("Upgrade:") {
                let mut wire = buffer(format!("HTTP/1.1 200 OK\r\n{framing}").as_bytes());
                reject_wire(&mut wire, false);
            }
        }
    }

    #[test]
    fn encoding_rejects_injection_and_length_mismatch_atomically() -> Result<()> {
        for (name, value) in [
            ("x-test\r\ninjected", "yes"),
            ("x-test", "yes\r\nInjected: true"),
            ("content-length", "99"),
        ] {
            let mut out = buffer(b"existing output");
            let before = out.clone();
            let request = Request::post("http://localhost/", "abc")?.with_header(name, value);
            rejected(Http1ClientCodec::default().encode_request(&request, &mut out));
            assert_eq!(out, before);
            let response = Response::ok("abc").with_header(name, value);
            rejected(Http1ServerCodec::default().encode_response(&response, &mut out));
            assert_eq!(out, before);
        }
        let mut request = Request::get("http://localhost/")?;
        request.version = Version::Http2;
        let mut out = BytesMut::new();
        rejected(Http1ClientCodec::default().encode_request(&request, &mut out));
        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn tls_rejects_untrusted_root_wrong_name_and_alpn_mismatch() -> Result<()> {
        let (server, certificate) =
            TlsServerConfig::self_signed_for_localhost(&[AlpnProtocol::Http11])?;
        let (other_server, other_certificate) =
            TlsServerConfig::self_signed_for_localhost(&[AlpnProtocol::Http11])?;
        let untrusted =
            TlsClientConfig::with_root_certificates(&[other_certificate], &[AlpnProtocol::Http11])?;
        let trusted = TlsClientConfig::with_root_certificates(
            std::slice::from_ref(&certificate),
            &[AlpnProtocol::Http11],
        )?;
        let mismatched =
            TlsClientConfig::with_root_certificates(&[certificate], &[AlpnProtocol::Http2])?;
        assert_tls_error(connect(&untrusted, &server, "localhost", 1));
        assert_tls_error(connect(&trusted, &server, "wrong.example", 1));
        assert_tls_error(connect(&mismatched, &server, "localhost", 1));
        assert_tls_error(connect(
            &TlsClientConfig::default(),
            &other_server,
            "localhost",
            31,
        ));
        Ok(())
    }

    #[test]
    fn one_byte_ciphertext_and_large_bidirectional_plaintext_preserve_bytes() -> Result<()> {
        let (mut client, mut server) = trusted_pair(1)?;
        let payload: Vec<u8> = (0..131_073).map(|index| (index % 251) as u8).collect();
        send(&mut client, &mut server, &payload, 1)?;
        send(&mut server, &mut client, &payload, 19)?;
        let mut out = buffer(b"prefix");
        assert_eq!(client.read_plaintext(&mut out)?, 0);
        assert_eq!(out.as_ref(), b"prefix");
        Ok(())
    }

    #[test]
    fn coalesced_ciphertext_larger_than_plaintext_buffer_drains_without_loss() -> Result<()> {
        let (mut client, mut server) = trusted_pair(23)?;
        let payload: Vec<u8> = (0..196_613).map(|index| (index % 239) as u8).collect();
        let mut ciphertext = BytesMut::new();
        let mut offset = 0;
        while offset < payload.len() {
            let count = client.write_plaintext(&payload[offset..])?;
            assert!(count > 0);
            offset += count;
            assert!(client.take_ciphertext(&mut ciphertext)? > 0);
        }
        let available = server.feed_ciphertext(ciphertext.as_ref())?;
        assert!(available > 0);
        assert!(available <= payload.len());
        let mut plaintext = buffer(b"prefix");
        assert_eq!(server.read_plaintext(&mut plaintext)?, payload.len());
        assert_eq!(&plaintext[..6], b"prefix");
        assert_eq!(&plaintext[6..], payload.as_slice());
        assert_eq!(server.read_plaintext(&mut plaintext)?, 0);
        Ok(())
    }

    #[test]
    fn eof_delimited_response_fails_without_an_eof_notification_api() {
        for head in [
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
        ] {
            let mut wire = buffer(head);
            wire.extend_from_slice(b"indeterminate body");
            let before = wire.clone();
            assert!(matches!(
                Http1ClientCodec::default().decode_response(&mut wire, Method::Get),
                Err(ProtoError::Http1Protocol(_))
            ));
            assert_eq!(wire, before);
        }
    }
}
