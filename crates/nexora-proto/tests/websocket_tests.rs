//! WebSocket protocol tests at the in-memory, sans-IO public API boundary.
//! HTTP codecs and byte buffers are real; socket, timer, and SDK behavior is outside this target.

use nexora_proto::{
    Bytes, BytesMut, Headers, Http1ClientCodec, Http1KeepAlive, Http1ServerCodec, Method,
    ProtoError, Result, StatusCode, Uri, Version, WebSocketCloseCode, WebSocketCloseFrame,
    WebSocketCodec, WebSocketConfig, WebSocketFrame, WebSocketHandshake, WebSocketMessage,
    WebSocketOpcode, WebSocketRole,
};

const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

#[path = "support/websocket.rs"]
mod websocket_support;
use websocket_support::*;

mod integration_tests {
    use super::*;

    #[test]
    fn rfc_handshake_vector_and_upgrade_fields() -> Result<()> {
        assert_eq!(
            WebSocketHandshake::compute_accept_key(RFC_KEY),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        let uri = Uri::parse("wss://example.com:8443/stream?topic=prices")?;
        let mut extra = Headers::new();
        extra.insert("x-session", "test-session");
        let request = WebSocketHandshake::build_upgrade_request(&uri, RFC_KEY, &extra);
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.version, Version::Http11);
        assert_eq!(request.uri.path_and_query(), "/stream?topic=prices");
        assert_eq!(request.header("host"), Some("example.com:8443"));
        assert_eq!(request.header("sec-websocket-version"), Some("13"));
        assert_eq!(request.header("x-session"), Some("test-session"));
        assert_eq!(
            WebSocketHandshake::validate_upgrade_request(&request)?,
            RFC_KEY
        );
        let response = WebSocketHandshake::build_upgrade_response(RFC_KEY);
        assert_eq!(response.status, StatusCode::SWITCHING_PROTOCOLS);
        WebSocketHandshake::validate_upgrade_response(&response, RFC_KEY)?;
        Ok(())
    }

    #[test]
    fn generated_nonce_is_valid_and_changes_with_seed() -> Result<()> {
        let uri = Uri::parse("ws://example.com/")?;
        let mut keys = std::collections::HashSet::new();
        for seed in [0, 1, 2, 17, u64::MAX] {
            let key = WebSocketHandshake::generate_key(seed);
            assert_eq!(key.len(), 24);
            assert!(key.ends_with("=="));
            let request = WebSocketHandshake::build_upgrade_request(&uri, &key, &Headers::new());
            assert_eq!(WebSocketHandshake::validate_upgrade_request(&request)?, key);
            assert!(keys.insert(key));
        }
        Ok(())
    }

    #[test]
    fn mandatory_upgrade_fields_override_extra_headers() -> Result<()> {
        let uri = Uri::parse("ws://example.com/stream")?;
        let mut extra = Headers::new();
        for (name, value) in [
            ("host", "attacker.invalid"),
            ("upgrade", "other"),
            ("connection", "close"),
            ("sec-websocket-key", "forged"),
            ("sec-websocket-version", "12"),
            ("content-length", "5"),
            ("transfer-encoding", "chunked"),
        ] {
            extra.append(name, value);
        }
        let request = WebSocketHandshake::build_upgrade_request(&uri, RFC_KEY, &extra);
        assert_eq!(
            WebSocketHandshake::validate_upgrade_request(&request)?,
            RFC_KEY
        );
        assert_eq!(request.header("host"), Some("example.com"));
        assert!(!request.headers.contains("content-length"));
        assert!(!request.headers.contains("transfer-encoding"));
        Ok(())
    }

    #[test]
    fn client_masking_matches_rfc_vector_and_server_unmasks() -> Result<()> {
        let mut source = buffer(&[
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ]);
        assert_eq!(
            WebSocketCodec::server_default().decode_message(&mut source)?,
            Some(WebSocketMessage::Text(String::from("Hello")))
        );
        assert!(source.is_empty());
        let mut client = WebSocketCodec::client_default();
        let mut server = WebSocketCodec::server_default();
        let mut masks = std::collections::HashSet::new();
        for _ in 0..8 {
            let mut encoded = BytesMut::new();
            client.encode_message(&WebSocketMessage::Text(String::from("Hello")), &mut encoded)?;
            assert_eq!(&encoded[..2], &[0x81, 0x85]);
            masks.insert(encoded[2..6].to_vec());
            for (index, byte) in b"Hello".iter().enumerate() {
                assert_eq!(encoded[6 + index] ^ encoded[2 + index % 4], *byte);
            }
            assert_eq!(
                server.decode_message(&mut encoded)?,
                Some(WebSocketMessage::Text(String::from("Hello")))
            );
        }
        assert!(
            masks.len() > 1,
            "client must generate a fresh mask for every frame"
        );
        Ok(())
    }

    #[test]
    fn canonical_extended_lengths_round_trip_both_roles() -> Result<()> {
        for size in [0, 125, 126, 65535, 65536] {
            let payload = vec![0xa5; size];
            for role in [WebSocketRole::Client, WebSocketRole::Server] {
                let mut sender = WebSocketCodec::new(role, WebSocketConfig::default());
                let mut receiver = WebSocketCodec::new(
                    if role == WebSocketRole::Client {
                        WebSocketRole::Server
                    } else {
                        WebSocketRole::Client
                    },
                    WebSocketConfig::default(),
                );
                let mut encoded = BytesMut::new();
                let message = WebSocketMessage::Binary(Bytes::copy_from_slice(&payload));
                sender.encode_message(&message, &mut encoded)?;
                let length = match size {
                    0..=125 => size as u8,
                    126..=65535 => 126,
                    _ => 127,
                };
                assert_eq!(encoded[1] & 0x7f, length);
                if size >= 65536 {
                    assert_eq!(&encoded[2..10], &(size as u64).to_be_bytes());
                } else if size >= 126 {
                    assert_eq!(&encoded[2..4], &(size as u16).to_be_bytes());
                }
                assert_eq!(receiver.decode_message(&mut encoded)?, Some(message));
                assert!(encoded.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn fragmented_utf8_survives_interleaved_ping_and_pong() -> Result<()> {
        let text = "A\u{a2}\u{20ac}\u{1f600}Z";
        for split in 0..=text.len() {
            let mut source = wire(false, 1, &text.as_bytes()[..split], true);
            source.extend_from_slice(&wire(false, 0, &[], true));
            source.extend_from_slice(&wire(true, 9, b"heartbeat", true));
            source.extend_from_slice(&wire(true, 10, b"ack", true));
            source.extend_from_slice(&wire(true, 0, &text.as_bytes()[split..], true));
            let mut codec = WebSocketCodec::server_default();
            for expected in [
                WebSocketMessage::Ping(Bytes::from("heartbeat")),
                WebSocketMessage::Pong(Bytes::from("ack")),
                WebSocketMessage::Text(text.to_owned()),
            ] {
                assert_eq!(codec.decode_message(&mut source)?, Some(expected));
            }
            assert!(source.is_empty());
        }
        Ok(())
    }

    #[test]
    fn encoder_fragmentation_is_decoded_without_exposing_partial_messages() -> Result<()> {
        let mut sender = WebSocketCodec::client_default();
        let mut receiver = WebSocketCodec::server_default();
        let mut stream = BytesMut::new();
        let text = "\u{1f600}";
        for (index, byte) in text.as_bytes().iter().enumerate() {
            let opcode = if index == 0 {
                WebSocketOpcode::Text
            } else {
                WebSocketOpcode::Continuation
            };
            let fin = index + 1 == text.len();
            sender.encode_frame(&frame(fin, opcode, &[*byte]), &mut stream)?;
            let expected = fin.then(|| WebSocketMessage::Text(text.to_owned()));
            assert_eq!(receiver.decode_message(&mut stream)?, expected);
        }
        Ok(())
    }
}

mod e2e_tests {
    use super::*;

    // The closed loop starts at HTTP upgrade construction and ends at decoded replies.
    // Buffers substitute for transport; this does not exercise the network SDK or TLS.
    #[test]
    fn in_memory_http_upgrade_preserves_first_frames_and_full_duplex_replies() -> Result<()> {
        let uri = Uri::parse("ws://localhost/stream")?;
        let request = WebSocketHandshake::build_upgrade_request(&uri, RFC_KEY, &Headers::new());
        let mut http_client = Http1ClientCodec::default();
        let mut http_server = Http1ServerCodec::default();
        let mut client = WebSocketCodec::client_default();
        let mut server = WebSocketCodec::server_default();
        let mut client_wire = BytesMut::new();
        http_client.encode_request(&request, &mut client_wire)?;
        client.encode_message(
            &WebSocketMessage::Text(String::from("first")),
            &mut client_wire,
        )?;
        let (decoded, keep_alive) = http_server
            .decode_request(&mut client_wire)?
            .ok_or(ProtoError::Incomplete)?;
        assert_eq!(keep_alive, Http1KeepAlive::Upgrade);
        let key = WebSocketHandshake::validate_upgrade_request(&decoded)?;
        let mut server_wire = BytesMut::new();
        http_server.encode_response(
            &WebSocketHandshake::build_upgrade_response(&key),
            &mut server_wire,
        )?;
        server.encode_message(
            &WebSocketMessage::Text(String::from("welcome")),
            &mut server_wire,
        )?;
        let (response, keep_alive) = http_client
            .decode_response(&mut server_wire, Method::Get)?
            .ok_or(ProtoError::Incomplete)?;
        assert_eq!(keep_alive, Http1KeepAlive::Upgrade);
        WebSocketHandshake::validate_upgrade_response(&response, RFC_KEY)?;
        assert_eq!(
            client.decode_message(&mut server_wire)?,
            Some(WebSocketMessage::Text(String::from("welcome")))
        );
        assert_eq!(
            server.decode_message(&mut client_wire)?,
            Some(WebSocketMessage::Text(String::from("first")))
        );
        let messages = [
            WebSocketMessage::Text(String::from("quote:123.45")),
            WebSocketMessage::Binary(Bytes::from(vec![0, 1, 255])),
            WebSocketMessage::Ping(Bytes::from("alive")),
        ];
        for message in messages {
            client.encode_message(&message, &mut client_wire)?;
            let delivered = server
                .decode_message(&mut client_wire)?
                .ok_or(ProtoError::Incomplete)?;
            assert_eq!(delivered, message);
            server.encode_message(&delivered, &mut server_wire)?;
            assert_eq!(client.decode_message(&mut server_wire)?, Some(message));
        }
        let payload = vec![0x5a; 65536];
        client.encode_frame(
            &frame(false, WebSocketOpcode::Binary, &payload[..32768]),
            &mut client_wire,
        )?;
        client.encode_frame(
            &frame(true, WebSocketOpcode::Continuation, &payload[32768..]),
            &mut client_wire,
        )?;
        assert_eq!(
            server.decode_message(&mut client_wire)?,
            Some(WebSocketMessage::Binary(Bytes::from(payload)))
        );
        assert!(client_wire.is_empty());
        assert!(server_wire.is_empty());
        Ok(())
    }
}

mod lifecycle_tests {
    use super::*;

    #[test]
    fn locally_closing_endpoint_answers_ping_until_peer_close() -> Result<()> {
        let mut codec = WebSocketCodec::client_default();
        let mut out = BytesMut::new();
        codec.encode_message(&normal_close(), &mut out)?;
        out.clear();
        assert_eq!(
            codec.decode_message(&mut wire(true, 9, b"last", false))?,
            Some(WebSocketMessage::Ping(Bytes::from("last")))
        );
        let pong = WebSocketMessage::Pong(Bytes::from("last"));
        codec.encode_message(&pong, &mut out)?;
        assert_eq!(
            WebSocketCodec::server_default().decode_message(&mut out)?,
            Some(pong.clone())
        );
        assert_eq!(
            codec.decode_message(&mut wire(true, 8, &[], false))?,
            Some(WebSocketMessage::Close(None))
        );
        assert!(codec.encode_message(&pong, &mut out).is_err());
        Ok(())
    }

    #[test]
    fn two_way_close_disallows_further_data() -> Result<()> {
        let mut client = WebSocketCodec::client_default();
        let mut server = WebSocketCodec::server_default();
        let mut outgoing = BytesMut::new();
        client.encode_message(&normal_close(), &mut outgoing)?;
        assert_eq!(server.decode_message(&mut outgoing)?, Some(normal_close()));
        assert!(
            client
                .encode_message(&WebSocketMessage::Text(String::from("late")), &mut outgoing)
                .is_err()
        );
        assert!(
            server
                .encode_message(
                    &WebSocketMessage::Binary(Bytes::from("late")),
                    &mut outgoing
                )
                .is_err()
        );
        server.encode_message(&normal_close(), &mut outgoing)?;
        assert_eq!(client.decode_message(&mut outgoing)?, Some(normal_close()));
        assert!(outgoing.is_empty());
        for endpoint in [&mut client, &mut server] {
            assert!(
                endpoint
                    .encode_message(&normal_close(), &mut outgoing)
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn close_interrupts_fragmented_message_without_delivering_partial_data() -> Result<()> {
        let mut codec = WebSocketCodec::server_default();
        let mut source = wire(false, 1, b"unfinished", true);
        source.extend_from_slice(&wire(true, 8, &[0x03, 0xe8], true));
        assert_eq!(
            codec.decode_message(&mut source)?,
            Some(WebSocketMessage::Close(Some(WebSocketCloseFrame {
                code: WebSocketCloseCode::Normal,
                reason: String::new(),
            })))
        );
        source.extend_from_slice(&wire(true, 0, b"tail", true));
        assert!(codec.decode_message(&mut source).is_err());
        Ok(())
    }

    #[test]
    fn consecutive_fragmented_messages_reset_reassembly_state() -> Result<()> {
        let mut codec = WebSocketCodec::client_default();
        for (opcode, expected) in [
            (1, WebSocketMessage::Text(String::from("abcd"))),
            (2, WebSocketMessage::Binary(Bytes::from("abcd"))),
        ] {
            let mut source = wire(false, opcode, b"ab", false);
            assert_eq!(codec.decode_message(&mut source)?, None);
            source.extend_from_slice(&wire(true, 0, b"cd", false));
            assert_eq!(codec.decode_message(&mut source)?, Some(expected));
            assert!(source.is_empty());
        }
        Ok(())
    }

    #[test]
    fn rejected_encode_is_atomic_and_does_not_prevent_valid_send() -> Result<()> {
        let config = WebSocketConfig {
            max_frame_size: 128,
            max_message_size: 3,
        };
        let mut codec = WebSocketCodec::new(WebSocketRole::Client, config);
        let mut out = buffer(b"prefix");
        let oversized = WebSocketMessage::Ping(Bytes::from(vec![0; 126]));
        assert!(codec.encode_message(&oversized, &mut out).is_err());
        assert_eq!(out.as_slice(), b"prefix");
        let invalid_close = frame(false, WebSocketOpcode::Close, &[]);
        assert!(codec.encode_frame(&invalid_close, &mut out).is_err());
        assert_eq!(out.as_slice(), b"prefix");
        codec.encode_frame(&frame(false, WebSocketOpcode::Text, &[0xe2]), &mut out)?;
        let ping = WebSocketMessage::Ping(Bytes::from("control"));
        codec.encode_message(&ping, &mut out)?;
        let before = out.clone();
        for payload in [&[0xff][..], &[0x82, 0xac, b'a'][..]] {
            let invalid = frame(true, WebSocketOpcode::Continuation, payload);
            let result = codec.encode_frame(&invalid, &mut out);
            if payload.len() == 1 {
                assert!(matches!(result, Err(ProtoError::InvalidUtf8(_))));
            } else {
                assert_eq!(
                    result,
                    Err(ProtoError::WebSocketMessageTooLarge { size: 4, max: 3 })
                );
            }
            assert_eq!(out, before);
        }
        codec.encode_frame(
            &frame(true, WebSocketOpcode::Continuation, &[0x82, 0xac]),
            &mut out,
        )?;
        let mut encoded = buffer(&out[6..]);
        let mut receiver = WebSocketCodec::new(WebSocketRole::Server, config);
        assert_eq!(receiver.decode_message(&mut encoded)?, Some(ping));
        assert_eq!(
            receiver.decode_message(&mut encoded)?,
            Some(WebSocketMessage::Text(String::from("\u{20ac}")))
        );
        Ok(())
    }
}

mod scenario_tests {
    use super::*;

    #[test]
    fn byte_trickle_and_coalesced_burst_deliver_identical_messages() -> Result<()> {
        let mut burst = wire(false, 1, b"tic", true);
        burst.extend_from_slice(&wire(true, 9, b"pulse", true));
        burst.extend_from_slice(&wire(true, 0, b"ker", true));
        burst.extend_from_slice(&wire(true, 2, &[0, 255, 1], true));
        burst.extend_from_slice(&wire(true, 1, b"next", true));
        let expected = vec![
            WebSocketMessage::Ping(Bytes::from("pulse")),
            WebSocketMessage::Text(String::from("ticker")),
            WebSocketMessage::Binary(Bytes::from(vec![0, 255, 1])),
            WebSocketMessage::Text(String::from("next")),
        ];
        for chunk_size in [1, 2, 7, burst.len()] {
            let mut decoder = WebSocketCodec::server_default();
            let mut pending = BytesMut::new();
            let mut delivered = Vec::new();
            for chunk in burst.chunks(chunk_size) {
                pending.extend_from_slice(chunk);
                while let Some(message) = decoder.decode_message(&mut pending)? {
                    delivered.push(message);
                }
            }
            assert_eq!(delivered, expected);
            assert!(pending.is_empty());
        }
        Ok(())
    }

    #[test]
    fn incomplete_frame_prefixes_are_retained_until_complete() -> Result<()> {
        let complete = wire(true, 2, &[42; 126], true);
        for end in 0..complete.len() {
            let mut codec = WebSocketCodec::server_default();
            let mut prefix = buffer(&complete[..end]);
            let original = prefix.clone();
            assert_eq!(codec.decode_message(&mut prefix)?, None);
            assert_eq!(prefix, original);
            prefix.extend_from_slice(&complete[end..]);
            assert_eq!(
                codec.decode_message(&mut prefix)?,
                Some(WebSocketMessage::Binary(Bytes::from(vec![42; 126])))
            );
        }
        Ok(())
    }

    #[test]
    fn role_mask_violations_are_rejected() {
        assert!(matches!(
            WebSocketCodec::server_default().decode_message(&mut wire(true, 1, b"unmasked", false)),
            Err(ProtoError::WebSocketProtocol(_))
        ));
        assert!(matches!(
            WebSocketCodec::client_default().decode_message(&mut wire(true, 1, b"masked", true)),
            Err(ProtoError::WebSocketProtocol(_))
        ));
    }

    #[test]
    fn reserved_bits_opcodes_and_noncanonical_lengths_are_rejected() {
        let malformed: &[&[u8]] = &[
            &[0xc1, 0],
            &[0xa1, 0],
            &[0x91, 0],
            &[0x83, 0],
            &[0x8b, 0],
            &[0x82, 126, 0, 1, 0],
            &[0x82, 127, 0, 0, 0, 0, 0, 0, 0, 1, 0],
            &[0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ];
        for bytes in malformed {
            assert!(
                matches!(
                    WebSocketCodec::client_default().decode_message(&mut buffer(bytes)),
                    Err(ProtoError::WebSocketProtocol(_))
                ),
                "accepted malformed header: {bytes:?}"
            );
        }
    }

    #[test]
    fn invalid_fragment_sequences_are_rejected() {
        assert!(decode_unmasked(true, 0, b"orphan").is_err());
        for next_opcode in [1, 2] {
            let mut stream = wire(false, 1, b"pending", false);
            stream.extend_from_slice(&wire(true, next_opcode, b"new message", false));
            let result = WebSocketCodec::client_default().decode_message(&mut stream);
            assert!(result.is_err());
        }
    }

    #[test]
    fn controls_require_fin_and_at_most_125_bytes() -> Result<()> {
        for opcode in [8, 9, 10] {
            assert!(decode_unmasked(false, opcode, &[]).is_err());
            assert!(decode_unmasked(true, opcode, &[0; 126]).is_err());
        }
        for opcode in [9, 10] {
            assert!(decode_unmasked(true, opcode, &[7; 125])?.is_some());
        }
        Ok(())
    }

    #[test]
    fn frame_and_message_limits_have_distinct_errors() -> Result<()> {
        let config = WebSocketConfig {
            max_frame_size: 4,
            max_message_size: 6,
        };
        let mut source = buffer(&[0x82, 5]);
        let mut limited = WebSocketCodec::new(WebSocketRole::Client, config);
        assert_eq!(
            limited.decode_message(&mut source),
            Err(ProtoError::WebSocketFrameTooLarge { size: 5, max: 4 })
        );
        let mut source = wire(false, 2, &[1; 4], false);
        source.extend_from_slice(&wire(true, 0, &[2; 3], false));
        assert_eq!(
            WebSocketCodec::new(WebSocketRole::Client, config).decode_message(&mut source),
            Err(ProtoError::WebSocketMessageTooLarge { size: 7, max: 6 })
        );
        let mut source = wire(false, 2, &[1; 3], false);
        source.extend_from_slice(&wire(true, 0, &[2; 3], false));
        assert_eq!(
            WebSocketCodec::new(WebSocketRole::Client, config).decode_message(&mut source)?,
            Some(WebSocketMessage::Binary(Bytes::from(vec![
                1, 1, 1, 2, 2, 2
            ])))
        );
        let mut out = BytesMut::new();
        let mut sender = WebSocketCodec::new(WebSocketRole::Server, config);
        for message in [
            WebSocketMessage::Binary(Bytes::from(vec![0; 5])),
            WebSocketMessage::Text("abcde".into()),
        ] {
            assert_eq!(
                sender.encode_message(&message, &mut out),
                Err(ProtoError::WebSocketFrameTooLarge { size: 5, max: 4 })
            );
        }
        assert!(out.is_empty());
        // A standalone final message is also subject to the message limit.
        let mut codec = WebSocketCodec::new(
            WebSocketRole::Client,
            WebSocketConfig {
                max_frame_size: 8,
                max_message_size: 3,
            },
        );
        let message = WebSocketMessage::Text("four".into());
        assert_eq!(
            codec.encode_message(&message, &mut out),
            Err(ProtoError::WebSocketMessageTooLarge { size: 4, max: 3 })
        );
        assert!(out.is_empty());
        assert_eq!(
            codec.decode_message(&mut wire(true, 2, &[0; 4], false)),
            Err(ProtoError::WebSocketMessageTooLarge { size: 4, max: 3 })
        );
        Ok(())
    }

    #[test]
    fn decoder_failure_remains_terminal_but_permits_one_error_close() -> Result<()> {
        let config = WebSocketConfig {
            max_frame_size: 4,
            max_message_size: 4,
        };
        for (mut invalid, code) in [
            (buffer(&[0xc1, 0]), WebSocketCloseCode::ProtocolError),
            (
                wire(true, 1, &[0xff], false),
                WebSocketCloseCode::InvalidFramePayloadData,
            ),
            (
                wire(true, 2, &[0; 5], false),
                WebSocketCloseCode::MessageTooBig,
            ),
        ] {
            let mut codec = WebSocketCodec::new(WebSocketRole::Client, config);
            assert!(codec.decode_message(&mut invalid).is_err());
            let mut valid = wire(true, 1, b"ok", false);
            assert!(codec.decode_message(&mut valid).is_err());
            let mut out = BytesMut::new();
            assert!(
                codec
                    .encode_message(&WebSocketMessage::Text(String::from("late")), &mut out)
                    .is_err()
            );
            let close = WebSocketMessage::Close(Some(WebSocketCloseFrame {
                code,
                reason: String::new(),
            }));
            codec.encode_message(&close, &mut out)?;
            assert_eq!(
                WebSocketCodec::server_default().decode_message(&mut out)?,
                Some(close.clone())
            );
            assert!(codec.encode_message(&close, &mut out).is_err());
        }
        Ok(())
    }

    #[test]
    fn utf8_validation_applies_to_text_and_close_reason() {
        for bytes in [
            &[0xff][..],
            &[0xc0, 0x80][..],
            &[0xed, 0xa0, 0x80][..],
            &[0xf4, 0x90, 0x80, 0x80][..],
        ] {
            assert!(matches!(
                decode_unmasked(true, 1, bytes),
                Err(ProtoError::InvalidUtf8(_))
            ));
        }
        let mut incomplete = wire(false, 1, &[0xe2], false);
        incomplete.extend_from_slice(&wire(true, 0, &[0x82], false));
        assert!(matches!(
            WebSocketCodec::client_default().decode_message(&mut incomplete),
            Err(ProtoError::InvalidUtf8(_))
        ));
        assert!(matches!(
            decode_unmasked(true, 8, &[0x03, 0xe8, 0xff]),
            Err(ProtoError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn close_payload_code_and_reason_constraints() -> Result<()> {
        for code in [0_u16, 999, 1004, 1005, 1006, 1015, 2000, 2999, 5000] {
            assert!(decode_unmasked(true, 8, &code.to_be_bytes()).is_err());
            let close = WebSocketMessage::Close(Some(WebSocketCloseFrame {
                code: WebSocketCloseCode::Custom(code),
                reason: String::new(),
            }));
            assert!(
                WebSocketCodec::server_default()
                    .encode_message(&close, &mut BytesMut::new())
                    .is_err()
            );
        }
        assert!(decode_unmasked(true, 8, &[0]).is_err());
        assert_eq!(
            decode_unmasked(true, 8, &[])?,
            Some(WebSocketMessage::Close(None))
        );
        for length in [123, 124] {
            let close = WebSocketMessage::Close(Some(WebSocketCloseFrame {
                code: WebSocketCloseCode::Normal,
                reason: "a".repeat(length),
            }));
            let result =
                WebSocketCodec::server_default().encode_message(&close, &mut BytesMut::new());
            assert_eq!(result.is_ok(), length == 123);
        }
        Ok(())
    }

    #[test]
    fn upgrade_request_rejects_invalid_method_version_and_required_headers() -> Result<()> {
        let uri = Uri::parse("ws://example.com/stream")?;
        let valid = WebSocketHandshake::build_upgrade_request(&uri, RFC_KEY, &Headers::new());
        for header in [
            "host",
            "upgrade",
            "connection",
            "sec-websocket-key",
            "sec-websocket-version",
        ] {
            let mut bad = valid.clone();
            bad.headers.remove(header);
            assert!(
                WebSocketHandshake::validate_upgrade_request(&bad).is_err(),
                "missing {header}"
            );
        }
        let mut bad = valid.clone();
        bad.method = Method::Post;
        assert!(WebSocketHandshake::validate_upgrade_request(&bad).is_err());
        bad = valid.clone();
        bad.version = Version::Http10;
        assert!(WebSocketHandshake::validate_upgrade_request(&bad).is_err());
        for key in [
            "",
            "not-base64",
            "YWJj",
            "dGhlIHNhbXBsZSBub25jZQ=",
            "dGhlIHNhbXBsZSBub25jZR==",
        ] {
            let mut bad = valid.clone();
            bad.headers.insert("sec-websocket-key", key);
            assert!(
                WebSocketHandshake::validate_upgrade_request(&bad).is_err(),
                "invalid key {key:?}"
            );
        }
        for (header, value) in [
            ("upgrade", "notwebsocket"),
            ("connection", "upgraded"),
            ("sec-websocket-version", "12"),
            ("host", "invalid host"),
            ("host", "example.com/path"),
            ("sec-websocket-protocol", "chat, chat"),
            ("sec-websocket-protocol", "bad token"),
            ("sec-websocket-extensions", ";;"),
            ("sec-websocket-extensions", "x; =bad"),
            ("sec-websocket-extensions", "x; p=\"bad token\""),
            ("sec-websocket-extensions", "x; p=\"unterminated"),
        ] {
            let mut bad = valid.clone();
            bad.headers.insert(header, value);
            assert!(WebSocketHandshake::validate_upgrade_request(&bad).is_err());
        }
        let mut tokens = valid;
        tokens.headers.insert("connection", "keep-alive, UpGrAdE");
        tokens.headers.insert("upgrade", "WebSocket");
        tokens
            .headers
            .insert("sec-websocket-protocol", "chat, CHAT");
        tokens
            .headers
            .insert("sec-websocket-extensions", r#"x; p="f\ast", y; bare"#);
        assert_eq!(
            WebSocketHandshake::validate_upgrade_request(&tokens)?,
            RFC_KEY
        );
        Ok(())
    }

    #[test]
    fn upgrade_response_rejects_invalid_status_accept_and_critical_duplicates() -> Result<()> {
        let valid = WebSocketHandshake::build_upgrade_response(RFC_KEY);
        let mut bad = valid.clone();
        bad.status = StatusCode::OK;
        assert!(WebSocketHandshake::validate_upgrade_response(&bad, RFC_KEY).is_err());
        bad = valid.clone();
        bad.version = Version::Http10;
        assert!(WebSocketHandshake::validate_upgrade_response(&bad, RFC_KEY).is_err());
        for header in ["upgrade", "connection", "sec-websocket-accept"] {
            let mut bad = valid.clone();
            bad.headers.remove(header);
            assert!(WebSocketHandshake::validate_upgrade_response(&bad, RFC_KEY).is_err());
        }
        bad = valid.clone();
        bad.headers.insert("content-length", "0");
        assert!(WebSocketHandshake::validate_upgrade_response(&bad, RFC_KEY).is_err());
        let other_key = WebSocketHandshake::generate_key(7);
        assert!(WebSocketHandshake::validate_upgrade_response(&valid, &other_key).is_err());
        bad = valid;
        bad.headers.append("sec-websocket-accept", "forged");
        assert!(WebSocketHandshake::validate_upgrade_response(&bad, RFC_KEY).is_err());
        let uri = Uri::parse("ws://example.com/")?;
        let mut request = WebSocketHandshake::build_upgrade_request(&uri, RFC_KEY, &Headers::new());
        request.headers.append("sec-websocket-key", RFC_KEY);
        assert!(WebSocketHandshake::validate_upgrade_request(&request).is_err());
        Ok(())
    }
}
