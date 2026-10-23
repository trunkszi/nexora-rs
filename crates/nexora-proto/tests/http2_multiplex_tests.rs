use nexora_proto::{
    AlpnProtocol, Bytes, BytesMut, Http2Config, Http2Connection, Http2ErrorCode, Http2Event,
    Http2Role, Http2Settings, ProtoError, Request, Response, Result, StatusCode, TlsClientConfig,
    TlsServerConfig, TlsSession, Version,
    http2::{
        CLIENT_PREFACE, DEFAULT_MAX_FRAME_SIZE, HpackEncoder, Http2Frame, decode_frame,
        encode_frame,
    },
};
#[path = "support/http2_multiplex.rs"]
mod http2_multiplex_support;
use http2_multiplex_support::*;

mod integration_tests {
    use super::*;
    #[test]
    fn authority_replaces_host_on_the_wire_without_weakening_validation() -> Result<()> {
        let mut client = Http2Connection::client_default();
        let mut server = Http2Connection::server_default();
        pump(&mut client, &mut server)?;
        events(&mut client);
        events(&mut server);
        let request = Request::get("https://localhost:8443/authority")?
            .with_header("host", "localhost:8443")
            .with_header("x-pass", "retained");
        let mut invalid = request.clone();
        invalid.headers.insert("host", "different.example");
        assert!(matches!(
            client.submit_request(&invalid),
            Err(ProtoError::Http2StreamError {
                code: Http2ErrorCode::ProtocolError,
                ..
            })
        ));
        assert_eq!(client.active_stream_count(), 0);
        assert_eq!(client.submit_request(&request)?, 1);
        pump(&mut client, &mut server)?;
        let received = events(&mut server);
        assert!(
            matches!(received.as_slice(), [Http2Event::RequestReceived { request, .. }]
            if request.uri.authority() == "localhost:8443"
                && request.header("host").is_none()
                && request.header("x-pass") == Some("retained"))
        );
        assert_eq!(request.header("host"), Some("localhost:8443"));
        Ok(())
    }
    #[test]
    #[rustfmt::skip]
    fn table_size_reduction_waits_for_initial_settings_acknowledgement() -> Result<()> {
        let mut client = Http2Connection::client_default();
        let config = Http2Config { local_settings: Http2Settings { header_table_size: 0, ..Http2Settings::default() }, ..Http2Config::default() };
        let mut server = Http2Connection::new(Http2Role::Server, config);
        let request = Request::get("https://localhost/table")?.with_header("x-dynamic", "retained-until-ack");
        for _ in 0..2 { client.submit_request(&request)?; }
        feed(&mut server, drain(&mut client).as_slice(), 1)?;
        assert_eq!(events(&mut server).iter().filter(|event| matches!(event, Http2Event::RequestReceived { request, .. } if request.header("x-dynamic") == Some("retained-until-ack"))).count(), 2);
        pump(&mut client, &mut server)?;
        events(&mut server);
        client.submit_request(&request)?;
        pump(&mut client, &mut server)?;
        assert!(matches!(events(&mut server).as_slice(), [Http2Event::RequestReceived { request, .. }] if request.header("x-dynamic") == Some("retained-until-ack")));
        Ok(())
    }
    #[test]
    #[rustfmt::skip]
    fn settings_delta_overflow_preserves_every_stream_window() -> Result<()> {
        let mut client = raw_client(Http2Settings { initial_window_size: 0, ..Http2Settings::default() })?;
        let first = client.submit_request(&request(0, 0)?)?;
        let second = client.submit_request(&request(1, 0)?)?;
        window(&mut client, second, 0x7fff_ffff)?;
        drain(&mut client);
        let sparse = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1];
        assert_connection_error(feed(&mut client, &sparse, 1), Http2ErrorCode::FlowControlError);
        assert_eq!((client.stream_send_window(first), client.stream_send_window(second)), (Some(0), Some(0x7fff_ffff)));
        assert!(!frames(drain(&mut client))?.iter().any(|frame| matches!(frame, Http2Frame::Settings { ack: true, .. })));
        Ok(())
    }
    #[test]
    #[rustfmt::skip]
    fn idle_frames_fail_while_closed_stream_frames_preserve_connection() -> Result<()> {
        for frame in [Http2Frame::Data { stream_id: 1, end_stream: true, data: Bytes::from("x") },
            Http2Frame::RstStream { stream_id: 1, error_code: Http2ErrorCode::Cancel },
            Http2Frame::WindowUpdate { stream_id: 1, increment: 1 }] {
            let mut idle = raw_client(Http2Settings::default())?;
            assert_connection_error(inject(&mut idle, frame), Http2ErrorCode::ProtocolError);
        }
        let mut client = raw_client(Http2Settings::default())?;
        let id = client.submit_request(&request(0, 0)?)?;
        client.cancel_stream(id)?;
        drain(&mut client);
        inject(&mut client, Http2Frame::Data { stream_id: id, end_stream: true, data: Bytes::from("late") })?;
        window(&mut client, id, 1)?;
        inject(&mut client, Http2Frame::RstStream { stream_id: id, error_code: Http2ErrorCode::Cancel })?;
        assert!(events(&mut client).is_empty());
        assert!(client.can_open_stream());
        Ok(())
    }
    #[test]
    fn preface_settings_ack_and_ping_survive_one_byte_input() -> Result<()> {
        let mut client = Http2Connection::client_default();
        let mut server = Http2Connection::server_default();
        assert_eq!(server.role(), Http2Role::Server);
        let wire = drain(&mut client);
        assert!(wire.starts_with(CLIENT_PREFACE));
        feed(&mut server, wire.as_slice(), 1)?;
        let server_wire = drain(&mut server);
        let server_frames = frames(server_wire.clone())?;
        assert!(
            matches!(server_frames.first(), Some(Http2Frame::Settings { settings, .. }) if !settings.enable_push)
        );
        feed(&mut client, server_wire.as_slice(), 1)?;
        pump(&mut client, &mut server)?;
        assert_eq!(events(&mut client), vec![Http2Event::SettingsAcknowledged]);
        assert_eq!(events(&mut server), vec![Http2Event::SettingsAcknowledged]);
        let opaque = *b"pingtest";
        client.send_ping(opaque)?;
        pump(&mut client, &mut server)?;
        assert_eq!(
            events(&mut client),
            vec![Http2Event::PingAcknowledged(opaque)]
        );
        assert!(events(&mut server).is_empty());
        assert_eq!(client.connection_send_window(), 65_535);
        Ok(())
    }
    #[test]
    fn malformed_preface_and_non_settings_first_frame_are_rejected() -> Result<()> {
        let mut server = Http2Connection::server_default();
        assert_connection_error(feed(&mut server, b"X", 1), Http2ErrorCode::ProtocolError);
        let mut server = Http2Connection::server_default();
        feed(&mut server, CLIENT_PREFACE, 1)?;
        assert_connection_error(
            inject(
                &mut server,
                Http2Frame::Ping {
                    ack: false,
                    opaque_data: [0; 8],
                },
            ),
            Http2ErrorCode::ProtocolError,
        );
        let mut client = raw_client(Http2Settings::default())?;
        assert_connection_error(
            inject(
                &mut client,
                Http2Frame::Settings {
                    ack: false,
                    settings: Http2Settings {
                        enable_push: true,
                        ..Http2Settings::default()
                    },
                },
            ),
            Http2ErrorCode::ProtocolError,
        );
        Ok(())
    }
    #[test]
    #[rustfmt::skip]
    fn completed_header_block_requires_contiguous_same_stream_continuations() -> Result<()> {
        let (_, mut server) = pair(Http2Config::default())?;
        let mut encoder = HpackEncoder::default();
        let mut block = BytesMut::new();
        encoder.encode(
            &[
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":authority".into(), "localhost".into()),
                (":path".into(), "/fragmented".into()),
            ],
            &mut block,
        );
        let split = block.len() / 2;
        inject(&mut server, headers(1, true, false, &block[..split]))?;
        assert!(events(&mut server).is_empty());
        inject(
            &mut server,
            Http2Frame::Continuation {
                stream_id: 1,
                end_headers: true,
                header_block: Bytes::copy_from_slice(&block[split..]),
            },
        )?;
        assert!(
            matches!(server.poll_event(), Some(Http2Event::RequestReceived { stream_id: 1, request }) if request.path() == "/fragmented")
        );
        for frame in [
            Http2Frame::Ping { ack: false, opaque_data: [0; 8] },
            Http2Frame::Continuation { stream_id: 3, end_headers: true, header_block: Bytes::new() },
        ] {
            let (_, mut server) = pair(Http2Config::default())?;
            inject(&mut server, headers(1, false, false, b""))?;
            assert_connection_error(inject(&mut server, frame), Http2ErrorCode::ProtocolError);
        }
        Ok(())
    }
    #[test]
    fn server_enforces_odd_monotonic_peer_stream_ids() -> Result<()> {
        for stream_id in [0, 2] {
            let (_, mut server) = pair(Http2Config::default())?;
            assert_connection_error(
                inject(
                    &mut server,
                    headers(stream_id, true, true, b"\x82\x87\x84\x01\x09localhost"),
                ),
                Http2ErrorCode::ProtocolError,
            );
        }
        let (_, mut server) = pair(Http2Config::default())?;
        inject(
            &mut server,
            headers(3, true, true, b"\x82\x87\x84\x01\x09localhost"),
        )?;
        assert_connection_error(
            inject(
                &mut server,
                headers(1, true, true, b"\x82\x87\x84\x01\x09localhost"),
            ),
            Http2ErrorCode::ProtocolError,
        );
        Ok(())
    }
    #[test]
    #[rustfmt::skip]
    fn connection_and_stream_window_overflow_are_rejected() -> Result<()> {
        let mut client = raw_client(Http2Settings::default())?;
        assert_connection_error(window(&mut client, 0, 0x7fff_ffff), Http2ErrorCode::FlowControlError);
        let mut client = raw_client(Http2Settings::default())?;
        let stream_id = client.submit_request(&Request::get("https://localhost/")?)?;
        assert!(matches!(window(&mut client, stream_id, 0x7fff_ffff),
            Err(ProtoError::Http2StreamError { stream_id: id, code: Http2ErrorCode::FlowControlError, .. }) if id == stream_id));
        assert_eq!(client.active_stream_count(), 0);
        assert!(client.can_open_stream());
        Ok(())
    }
    #[test]
    fn sparse_settings_preserve_prior_unmentioned_peer_values() -> Result<()> {
        let mut client = raw_client(Http2Settings {
            initial_window_size: 20_000,
            max_concurrent_streams: 1,
            ..Http2Settings::default()
        })?;
        let stream_id = client.submit_request(&request(0, 0)?)?;
        drain(&mut client);
        let sparse = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 3, 232];
        feed(&mut client, &sparse, 1)?;
        assert_eq!(client.stream_send_window(stream_id), Some(1_000));
        assert!(!client.can_open_stream());
        assert!(
            frames(drain(&mut client))?
                .iter()
                .any(|frame| matches!(frame, Http2Frame::Settings { ack: true, .. }))
        );
        Ok(())
    }
    #[test]
    #[rustfmt::skip]
    fn padded_data_credits_stream_and_connection_and_enforces_padding_window() -> Result<()> {
        for length in [8, 9] {
            let config = Http2Config { local_settings: Http2Settings { initial_window_size: 8, ..Http2Settings::default() }, ..Http2Config::default() };
            let (mut client, mut server) = pair(config)?;
            let stream_id = client.submit_request(&Request::post("https://localhost/padded", vec![1, 2, 3])?)?;
            for frame in frames(drain(&mut client))? {
                if !matches!(frame, Http2Frame::Data { .. }) { inject(&mut server, frame)?; }
            }
            let mut wire = BytesMut::new();
            wire.extend_from_slice(&[0, 0, length, 0, 8]);
            wire.extend_from_slice(&stream_id.to_be_bytes());
            wire.extend_from_slice(&[length - 4, 1, 2, 3]);
            wire.resize(9 + usize::from(length), 0);
            let received = server.feed_bytes(&mut wire);
            if length == 9 {
                assert!(matches!(received, Err(ProtoError::Http2StreamError { stream_id: id, code: Http2ErrorCode::FlowControlError, .. }) if id == stream_id));
                assert!(events(&mut server).is_empty());
            } else {
                received?;
                assert!(events(&mut server).is_empty());
                let credits = frames(drain(&mut server))?;
                for id in [0, stream_id] {
                    assert!(credits.contains(&Http2Frame::WindowUpdate { stream_id: id, increment: 8 }));
                }
                inject(&mut server, Http2Frame::Data { stream_id, end_stream: true, data: Bytes::new() })?;
                assert!(matches!(server.poll_event(), Some(Http2Event::RequestReceived { request, .. }) if request.body.as_slice() == [1, 2, 3]));
            }
        }
        Ok(())
    }
}
mod e2e_tests {
    use super::*;
    fn submit_64(client: &mut Http2Connection) -> Result<Vec<u32>> {
        let mut ids = Vec::new();
        for index in 0..64 {
            ids.push(client.submit_request(&request(index, 257)?)?);
        }
        assert_eq!(ids, (0..64).map(|index| index * 2 + 1).collect::<Vec<_>>());
        assert_eq!(client.active_stream_count(), 64);
        Ok(ids)
    }
    #[rustfmt::skip]
    fn echo_reverse(server: &mut Http2Connection) -> Result<()> {
        let requests = events(server);
        assert_eq!((requests.len(), server.active_stream_count()), (64, 64));
        for event in requests.into_iter().rev() {
            let Http2Event::RequestReceived { stream_id, request } = event else { panic!("unexpected request event"); };
            let index = ((stream_id - 1) / 2) as usize;
            assert_eq!(request.path(), format!("/items/{index}"));
            assert_eq!(request.version, Version::Http2);
            assert_eq!(request.body.as_slice(), vec![index as u8; 257]);
            server.submit_response(stream_id, &Response::ok(request.body))?;
        }
        Ok(())
    }
    #[rustfmt::skip]
    fn check_64(client: &mut Http2Connection, server: &Http2Connection) {
        let mut ids = Vec::new();
        for event in events(client) {
            let Http2Event::ResponseReceived { stream_id, response } = event else { panic!("unexpected response event"); };
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(response.version, Version::Http2);
            assert_eq!(response.body.as_slice(), vec![((stream_id - 1) / 2) as u8; 257]);
            ids.push(stream_id);
        }
        ids.sort_unstable();
        assert_eq!(ids, (0..64).map(|index| index * 2 + 1).collect::<Vec<_>>());
        assert_eq!((client.active_stream_count(), server.active_stream_count()), (0, 0));
    }
    #[test]
    fn h2c_64_streams_interleave_data_and_reverse_response_order() -> Result<()> {
        let (mut client, mut server) = pair(Http2Config::default())?;
        submit_64(&mut client)?;
        let outbound = frames(drain(&mut client))?;
        let (data, headers): (Vec<_>, Vec<_>) = outbound
            .into_iter()
            .partition(|frame| matches!(frame, Http2Frame::Data { .. }));
        let mut wire = BytesMut::new();
        for frame in headers.into_iter().chain(data.into_iter().rev()) {
            encode_frame(&frame, &mut wire)?;
        }
        feed(&mut server, wire.as_slice(), 1)?;
        pump(&mut client, &mut server)?;
        echo_reverse(&mut server)?;
        pump(&mut client, &mut server)?;
        check_64(&mut client, &server);
        Ok(())
    }
    fn tls_transfer(from: &mut TlsSession, to: &mut TlsSession) -> Result<()> {
        let mut wire = BytesMut::new();
        from.take_ciphertext(&mut wire)?;
        for chunk in wire.chunks(113) {
            to.feed_ciphertext(chunk)?;
        }
        Ok(())
    }
    #[rustfmt::skip]
    fn tls_pump(client: &mut Http2Connection, server: &mut Http2Connection, ct: &mut TlsSession, st: &mut TlsSession) -> Result<()> {
        for _ in 0..512 {
            let wire = drain(client);
            if !wire.is_empty() { assert_eq!(ct.write_plaintext(wire.as_slice())?, wire.len()); }
            tls_transfer(ct, st)?;
            let mut plain = BytesMut::new();
            st.read_plaintext(&mut plain)?;
            feed(server, plain.as_slice(), 17)?;
            let wire = drain(server);
            if !wire.is_empty() { assert_eq!(st.write_plaintext(wire.as_slice())?, wire.len()); }
            tls_transfer(st, ct)?;
            let mut plain = BytesMut::new();
            ct.read_plaintext(&mut plain)?;
            feed(client, plain.as_slice(), 19)?;
            if !client.has_tx_bytes() && !server.has_tx_bytes() && !ct.wants_write() && !st.wants_write() { return Ok(()); }
        }
        panic!("TLS HTTP/2 peers did not reach quiescence");
    }
    #[test]
    fn tls_alpn_http2_64_stream_request_response_closed_loop() -> Result<()> {
        let (server_config, certificate) =
            TlsServerConfig::self_signed_for_localhost(&[AlpnProtocol::Http2])?;
        let client_config =
            TlsClientConfig::with_root_certificates(&[certificate], &[AlpnProtocol::Http2])?;
        let mut ct = TlsSession::new_client(&client_config, "localhost")?;
        let mut st = TlsSession::new_server(&server_config)?;
        for _ in 0..64 {
            tls_transfer(&mut ct, &mut st)?;
            tls_transfer(&mut st, &mut ct)?;
            if !ct.is_handshaking() && !st.is_handshaking() {
                break;
            }
        }
        assert!(!ct.is_handshaking() && !st.is_handshaking());
        assert_eq!(ct.alpn_protocol(), Some(AlpnProtocol::Http2));
        assert_eq!(st.alpn_protocol(), Some(AlpnProtocol::Http2));
        let mut client = Http2Connection::client_default();
        let mut server = Http2Connection::server_default();
        tls_pump(&mut client, &mut server, &mut ct, &mut st)?;
        assert_eq!(events(&mut client), vec![Http2Event::SettingsAcknowledged]);
        assert_eq!(events(&mut server), vec![Http2Event::SettingsAcknowledged]);
        submit_64(&mut client)?;
        tls_pump(&mut client, &mut server, &mut ct, &mut st)?;
        echo_reverse(&mut server)?;
        tls_pump(&mut client, &mut server, &mut ct, &mut st)?;
        check_64(&mut client, &server);
        Ok(())
    }
}
mod lifecycle_tests {
    use super::*;
    #[test]
    #[rustfmt::skip]
    fn malformed_stream_frame_is_consumed_and_sibling_completes() -> Result<()> {
        let (mut client, mut server) = pair(Http2Config::default())?;
        let rejected = client.submit_request(&request(0, 0)?)?;
        let sibling = client.submit_request(&request(1, 0)?)?;
        pump(&mut client, &mut server)?;
        events(&mut server);
        server.submit_response(sibling, &Response::ok("survived"))?;
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&[0, 0, 4, 8, 0]);
        wire.extend_from_slice(&rejected.to_be_bytes());
        wire.extend_from_slice(&[0; 4]);
        let trailing = drain(&mut server);
        wire.extend_from_slice(trailing.as_slice());
        assert!(matches!(client.feed_bytes(&mut wire),
            Err(ProtoError::Http2StreamError { stream_id, code: Http2ErrorCode::ProtocolError, .. }) if stream_id == rejected));
        assert_eq!(wire.as_slice(), trailing.as_slice());
        client.feed_bytes(&mut wire)?;
        assert!(wire.is_empty());
        assert!(matches!(events(&mut client).as_slice(),
            [Http2Event::ResponseReceived { stream_id, response }] if *stream_id == sibling && response.body.as_slice() == b"survived"));
        assert_eq!(client.active_stream_count(), 0);
        Ok(())
    }
    #[test]
    #[rustfmt::skip]
    fn goaway_cutoff_refuses_only_higher_streams_once() -> Result<()> {
        let (mut client, mut server) = pair(Http2Config::default())?;
        let accepted = client.submit_request(&request(0, 0)?)?;
        let refused = client.submit_request(&request(1, 0)?)?;
        pump(&mut client, &mut server)?;
        events(&mut server);
        assert!(server.send_goaway(accepted, Http2ErrorCode::NoError, Bytes::new()).is_err());
        assert!(!server.has_tx_bytes());
        inject(&mut client, Http2Frame::GoAway { last_stream_id: accepted, error_code: Http2ErrorCode::NoError, debug_data: Bytes::new() })?;
        server.submit_response(accepted, &Response::ok("accepted"))?;
        pump(&mut client, &mut server)?;
        let received = events(&mut client);
        assert_eq!(received.iter().filter(|event| matches!(event,
            Http2Event::StreamReset { stream_id, error_code: Http2ErrorCode::RefusedStream } if *stream_id == refused)).count(), 1);
        assert!(received.iter().any(|event| matches!(event,
            Http2Event::ResponseReceived { stream_id, response } if *stream_id == accepted && response.body.as_slice() == b"accepted")));
        inject(&mut client, Http2Frame::GoAway { last_stream_id: accepted, error_code: Http2ErrorCode::NoError, debug_data: Bytes::new() })?;
        assert!(events(&mut client).iter().all(|event| matches!(event, Http2Event::GoAwayReceived { .. })));
        assert_eq!(client.active_stream_count(), 0);
        assert!(!client.can_open_stream());
        Ok(())
    }
    #[test]
    fn cancelled_stream_headers_keep_sibling_hpack_context_synchronized() -> Result<()> {
        let mut client = raw_client(Http2Settings::default())?;
        let cancelled = client.submit_request(&request(0, 0)?)?;
        client.cancel_stream(cancelled)?;
        let sibling = client.submit_request(&request(1, 0)?)?;
        let mut encoder = HpackEncoder::default();
        let fields = vec![
            (":status".into(), "200".into()),
            ("x-history".into(), "retained".into()),
        ];
        for stream_id in [cancelled, sibling] {
            let mut block = BytesMut::new();
            encoder.encode(&fields, &mut block);
            inject(
                &mut client,
                Http2Frame::Headers {
                    stream_id,
                    end_stream: true,
                    end_headers: true,
                    header_block: block.freeze(),
                },
            )?;
        }
        let received = events(&mut client);
        assert_eq!(received.len(), 1);
        assert!(
            matches!(&received[0], Http2Event::ResponseReceived { stream_id, response }
            if *stream_id == sibling && response.header("x-history") == Some("retained"))
        );
        assert_eq!(client.active_stream_count(), 0);
        Ok(())
    }
    #[test]
    fn cancel_isolated_stream_preserves_siblings_and_connection_reuse() -> Result<()> {
        let (mut client, mut server) = pair(Http2Config::default())?;
        let cancelled = client.submit_request(&request(0, 0)?)?;
        let sibling = client.submit_request(&request(1, 1)?)?;
        pump(&mut client, &mut server)?;
        assert_eq!(events(&mut server).len(), 2);
        client.cancel_stream(cancelled)?;
        pump(&mut client, &mut server)?;
        assert_eq!(
            events(&mut server),
            vec![Http2Event::StreamReset {
                stream_id: cancelled,
                error_code: Http2ErrorCode::Cancel
            }]
        );
        assert_eq!(client.active_stream_count(), 1);
        assert_eq!(server.active_stream_count(), 1);
        server.submit_response(sibling, &Response::ok("sibling"))?;
        pump(&mut client, &mut server)?;
        let received = events(&mut client);
        assert_eq!(received.iter().filter(|event| matches!(event, Http2Event::ResponseReceived { stream_id, response } if *stream_id == sibling && response.body.as_slice() == b"sibling")).count(), 1);
        assert_eq!(client.active_stream_count(), 0);
        assert_eq!(server.active_stream_count(), 0);
        assert!(client.can_open_stream());
        assert_eq!(client.submit_request(&request(2, 0)?)?, 5);
        Ok(())
    }
    #[test]
    fn two_step_goaway_blocks_new_streams_and_drains_existing_requests() -> Result<()> {
        let (mut client, mut server) = pair(Http2Config::default())?;
        let first = client.submit_request(&request(0, 1)?)?;
        let second = client.submit_request(&request(1, 1)?)?;
        pump(&mut client, &mut server)?;
        assert_eq!(events(&mut server).len(), 2);
        server.send_goaway(
            0x7fff_ffff,
            Http2ErrorCode::NoError,
            Bytes::from("draining"),
        )?;
        pump(&mut client, &mut server)?;
        assert!(!client.can_open_stream());
        assert!(client.submit_request(&request(2, 0)?).is_err());
        server.send_goaway(second, Http2ErrorCode::NoError, Bytes::new())?;
        server.submit_response(second, &Response::ok("second"))?;
        server.submit_response(first, &Response::ok("first"))?;
        pump(&mut client, &mut server)?;
        let received = events(&mut client);
        assert_eq!(
            received
                .iter()
                .filter(|event| matches!(event, Http2Event::GoAwayReceived { .. }))
                .count(),
            2
        );
        assert_eq!(
            received
                .iter()
                .filter(|event| matches!(event, Http2Event::ResponseReceived { .. }))
                .count(),
            2
        );
        assert_eq!(client.active_stream_count(), 0);
        assert_eq!(server.active_stream_count(), 0);
        Ok(())
    }
    #[test]
    fn peer_stream_limit_reopens_when_an_existing_stream_completes() -> Result<()> {
        let config = Http2Config {
            local_settings: Http2Settings {
                max_concurrent_streams: 1,
                ..Http2Settings::default()
            },
            ..Http2Config::default()
        };
        let (mut client, mut server) = pair(config)?;
        let first = client.submit_request(&request(0, 0)?)?;
        assert!(!client.can_open_stream());
        assert!(client.submit_request(&request(1, 0)?).is_err());
        pump(&mut client, &mut server)?;
        server.submit_response(first, &Response::ok("done"))?;
        pump(&mut client, &mut server)?;
        assert!(client.can_open_stream());
        assert_eq!(client.submit_request(&request(2, 0)?)?, 3);
        Ok(())
    }
}
mod scenario_tests {
    use super::*;
    #[test]
    #[rustfmt::skip]
    fn response_semantics_suppress_data_for_head_204_and_304() -> Result<()> {
        for (method, status) in [(nexora_proto::Method::Head, StatusCode::OK),
            (nexora_proto::Method::Get, StatusCode::NO_CONTENT),
            (nexora_proto::Method::Get, StatusCode(304))] {
            let (mut client, mut server) = pair(Http2Config::default())?;
            let mut request = Request::get("https://localhost/bodyless")?;
            request.method = method;
            let id = client.submit_request(&request)?;
            pump(&mut client, &mut server)?;
            events(&mut server);
            server.submit_response(id, &Response::new(status).with_body("representation"))?;
            let outbound = drain(&mut server);
            assert!(frames(outbound.clone())?.iter().all(|frame| !matches!(frame, Http2Frame::Data { .. })));
            feed(&mut client, outbound.as_slice(), 1)?;
            assert!(matches!(events(&mut client).as_slice(),
                [Http2Event::ResponseReceived { response, .. }] if response.status == status && response.body.is_empty()));
            assert_eq!(client.active_stream_count(), 0);
        }
        Ok(())
    }
    #[test]
    fn signed_negative_stream_window_pauses_until_positive_update() -> Result<()> {
        let initial = Http2Settings {
            initial_window_size: 20_000,
            enable_push: false,
            ..Http2Settings::default()
        };
        let mut client = raw_client(initial)?;
        let stream_id = client.submit_request(&request(7, 30_000)?)?;
        let mut body = data_bytes(drain(&mut client))?;
        assert_eq!(body.len(), 20_000);
        assert_eq!(client.stream_send_window(stream_id), Some(0));
        let connection_window = client.connection_send_window();
        inject(
            &mut client,
            Http2Frame::Settings {
                ack: false,
                settings: Http2Settings {
                    initial_window_size: 1_000,
                    ..initial
                },
            },
        )?;
        assert_eq!(client.stream_send_window(stream_id), Some(-19_000));
        assert_eq!(client.connection_send_window(), connection_window);
        assert!(data_bytes(drain(&mut client))?.is_empty());
        window(&mut client, stream_id, 19_000)?;
        assert_eq!(client.stream_send_window(stream_id), Some(0));
        assert!(data_bytes(drain(&mut client))?.is_empty());
        window(&mut client, stream_id, 1)?;
        let resumed = data_bytes(drain(&mut client))?;
        assert_eq!(resumed.len(), 1);
        body.extend(resumed);
        window(&mut client, stream_id, 10_000)?;
        body.extend(data_bytes(drain(&mut client))?);
        assert_eq!(body, vec![7; 30_000]);
        assert_eq!(client.stream_send_window(stream_id), Some(1));
        Ok(())
    }
    #[test]
    fn sixty_four_large_streams_recover_both_flow_control_windows() -> Result<()> {
        let config = Http2Config {
            local_settings: Http2Settings {
                initial_window_size: 1_024,
                ..Http2Settings::default()
            },
            ..Http2Config::default()
        };
        let (mut client, mut server) = pair(config)?;
        for index in 0..64 {
            client.submit_request(&request(index, 70_000)?)?;
        }
        assert!(client.connection_send_window() < 1_024);
        inject(
            &mut client,
            Http2Frame::Settings {
                ack: false,
                settings: Http2Settings {
                    initial_window_size: 512,
                    enable_push: false,
                    ..config.local_settings
                },
            },
        )?;
        assert!(
            client
                .stream_send_window(1)
                .is_some_and(|window| window < 0)
        );
        for frame in frames(drain(&mut client))? {
            if !matches!(frame, Http2Frame::Settings { ack: true, .. }) {
                inject(&mut server, frame)?;
            }
        }
        pump(&mut client, &mut server)?;
        let requests = events(&mut server);
        assert_eq!(requests.len(), 64);
        for event in requests {
            let Http2Event::RequestReceived { stream_id, request } = event else {
                panic!("unexpected request event");
            };
            assert_eq!(
                request.body.as_slice(),
                vec![((stream_id - 1) / 2) as u8; 70_000]
            );
            server.submit_response(stream_id, &Response::ok("complete"))?;
        }
        pump(&mut client, &mut server)?;
        assert_eq!(
            events(&mut client)
                .iter()
                .filter(|event| matches!(event, Http2Event::ResponseReceived { .. }))
                .count(),
            64
        );
        assert_eq!(client.active_stream_count(), 0);
        assert_eq!(server.active_stream_count(), 0);
        Ok(())
    }
    #[test]
    fn oversized_request_emits_one_terminal_event_and_preserves_sibling() -> Result<()> {
        let (mut client, mut server) = pair(Http2Config {
            max_body_size: 4,
            ..Http2Config::default()
        })?;
        let rejected = client.submit_request(&request(0, 5)?)?;
        let sibling = client.submit_request(&request(1, 4)?)?;
        pump(&mut client, &mut server)?;
        let received = events(&mut server);
        assert_eq!(received.iter().filter(|event| matches!(event, Http2Event::StreamBodyTooLarge { stream_id, size: 5, max: 4 } if *stream_id == rejected)).count(), 1);
        assert_eq!(received.iter().filter(|event| matches!(event, Http2Event::RequestReceived { stream_id, .. } if *stream_id == sibling)).count(), 1);
        assert!(!received.iter().any(|event| matches!(event, Http2Event::RequestReceived { stream_id, .. } if *stream_id == rejected)));
        let client_events = events(&mut client);
        assert!(client_events.iter().any(|event| matches!(event,
            Http2Event::StreamReset { stream_id, .. } if *stream_id == rejected
        ) || matches!(event,
            Http2Event::ResponseReceived { stream_id, response } if *stream_id == rejected && response.status == StatusCode::PAYLOAD_TOO_LARGE
        )));
        server.submit_response(sibling, &Response::ok("ok"))?;
        pump(&mut client, &mut server)?;
        assert!(events(&mut client).iter().any(|event| matches!(event, Http2Event::ResponseReceived { stream_id, .. } if *stream_id == sibling)));
        Ok(())
    }
    #[test]
    fn oversized_response_sends_cancel_without_completing_the_body() -> Result<()> {
        let mut client = Http2Connection::new(
            Http2Role::Client,
            Http2Config {
                max_body_size: 4,
                ..Http2Config::default()
            },
        );
        let mut server = Http2Connection::server_default();
        pump(&mut client, &mut server)?;
        events(&mut client);
        events(&mut server);
        let stream_id = client.submit_request(&request(0, 0)?)?;
        pump(&mut client, &mut server)?;
        events(&mut server);
        server.submit_response(stream_id, &Response::ok("12345"))?;
        feed(&mut client, drain(&mut server).as_slice(), 1)?;
        let reset = drain(&mut client);
        assert!(frames(reset.clone())?.contains(&Http2Frame::RstStream {
            stream_id,
            error_code: Http2ErrorCode::Cancel,
        }));
        feed(&mut server, reset.as_slice(), 1)?;
        assert_eq!(
            events(&mut client),
            vec![Http2Event::StreamBodyTooLarge {
                stream_id,
                size: 5,
                max: 4
            }]
        );
        assert_eq!(client.active_stream_count(), 0);
        Ok(())
    }
}
