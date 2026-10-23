//! Public in-memory compression, framing, and HTTP/2 exchange contracts.

use nexora_proto::{
    Bytes, BytesMut, Http2Connection, Http2ErrorCode, Http2Event, ProtoError, Request, Response,
    Result,
    http2::{
        DEFAULT_MAX_FRAME_SIZE, HpackDecoder, HpackEncoder, Http2Frame, Http2FrameHeader,
        Http2FrameType, Http2Settings, decode_frame, encode_frame, huffman_decode, huffman_encode,
        huffman_encoded_len,
    },
};

fn hex(input: &str) -> Vec<u8> {
    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid hexadecimal fixture"),
        }
    }
    let (pairs, trailing) = input.as_bytes().as_chunks::<2>();
    assert!(trailing.is_empty());
    pairs
        .iter()
        .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
        .collect()
}

fn fields(input: &[(&str, &str)]) -> Vec<(String, String)> {
    input
        .iter()
        .map(|&(name, value)| (name.into(), value.into()))
        .collect()
}

fn raw(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> BytesMut {
    let mut out = BytesMut::new();
    out.put_u24(payload.len() as u32);
    out.put_u8(kind);
    out.put_u8(flags);
    out.put_u32(stream_id);
    out.extend_from_slice(payload);
    out
}

fn decoded(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Result<Option<Http2Frame>> {
    let mut input = raw(kind, flags, stream_id, payload);
    decode_frame(&mut input, DEFAULT_MAX_FRAME_SIZE)
}

fn connection_error(result: Result<Option<Http2Frame>>, expected: Http2ErrorCode) {
    assert!(
        matches!(result, Err(ProtoError::Http2ConnectionError { code, .. }) if code == expected)
    );
}

fn compression_error(block: &[u8]) {
    assert!(matches!(
        HpackDecoder::default().decode(block),
        Err(ProtoError::Hpack(_))
    ));
}

mod integration_tests {
    use super::*;

    #[test]
    fn rfc7541_request_vectors_with_and_without_huffman_share_dynamic_context() -> Result<()> {
        let expected = [
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ]),
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ]),
            fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ]),
        ];
        // RFC 7541 Appendices C.3 and C.4 use independent compression contexts.
        for blocks in [
            [
                "828684410f7777772e6578616d706c652e636f6d",
                "828684be58086e6f2d6361636865",
                "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
            ],
            [
                "828684418cf1e3c2e5f23a6ba0ab90f4ff",
                "828684be5886a8eb10649cbf",
                "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
            ],
        ] {
            let mut decoder = HpackDecoder::default();
            for (block, headers) in blocks.into_iter().zip(&expected) {
                assert_eq!(decoder.decode(&hex(block))?, *headers);
            }
        }
        Ok(())
    }

    #[test]
    fn all_61_static_indices_resolve_exact_names_and_values() -> Result<()> {
        let expected: Vec<_> = concat!(
            ":authority=;:method=GET;:method=POST;:path=/;:path=/index.html;",
            ":scheme=http;:scheme=https;:status=200;:status=204;:status=206;",
            ":status=304;:status=400;:status=404;:status=500;accept-charset=;",
            "accept-encoding=gzip, deflate;accept-language=;accept-ranges=;accept=;",
            "access-control-allow-origin=;age=;allow=;authorization=;cache-control=;",
            "content-disposition=;content-encoding=;content-language=;content-length=;",
            "content-location=;content-range=;content-type=;cookie=;date=;etag=;",
            "expect=;expires=;from=;host=;if-match=;if-modified-since=;if-none-match=;",
            "if-range=;if-unmodified-since=;last-modified=;link=;location=;max-forwards=;",
            "proxy-authenticate=;proxy-authorization=;range=;referer=;refresh=;retry-after=;",
            "server=;set-cookie=;strict-transport-security=;transfer-encoding=;",
            "user-agent=;vary=;via=;www-authenticate="
        )
        .split(';')
        .map(|entry| {
            let Some((name, value)) = entry.split_once('=') else {
                panic!("invalid static table fixture");
            };
            (String::from(name), String::from(value))
        })
        .collect();
        let block: Vec<u8> = (1..=61).map(|index| 0x80 | index).collect();
        assert_eq!(HpackDecoder::default().decode(&block)?, expected);
        Ok(())
    }

    #[test]
    fn huffman_known_vectors_round_trip() -> Result<()> {
        for (plain, encoded) in [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-key", "25a849e95ba97d7f"),
            ("custom-value", "25a849e95bb8e8b4bf"),
        ] {
            let mut out = BytesMut::new();
            huffman_encode(plain.as_bytes(), &mut out);
            assert_eq!(out.as_slice(), hex(encoded));
            assert_eq!(huffman_encoded_len(plain.as_bytes()), out.len());
            assert_eq!(huffman_decode(out.as_slice())?, plain.as_bytes());
        }
        assert_eq!(huffman_decode(&[])?, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn literal_indexing_modes_accept_new_and_indexed_names() -> Result<()> {
        for prefix in [0x00, 0x10, 0x40] {
            let mut decoder = HpackDecoder::default();
            assert_eq!(
                decoder.decode(&[prefix, 1, b'x', 1, b'a'])?,
                fields(&[("x", "a")])
            );
            if prefix == 0x40 {
                assert_eq!(decoder.decode(&[0xbe])?, fields(&[("x", "a")]));
            } else {
                assert!(matches!(decoder.decode(&[0xbe]), Err(ProtoError::Hpack(_))));
            }
        }
        for block in [
            &[0x0f, 0x10, 1, b'v'][..],
            &[0x1f, 0x10, 1, b'v'],
            &[0x5f, 1, b'v'],
        ] {
            assert_eq!(
                HpackDecoder::default().decode(block)?,
                fields(&[("content-type", "v")])
            );
        }
        Ok(())
    }

    #[test]
    fn sensitive_fields_remain_never_indexed_across_repeated_encodes() -> Result<()> {
        for name in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        ] {
            let headers = fields(&[(name, "private-value")]);
            let mut encoder = HpackEncoder::default();
            let mut decoder = HpackDecoder::default();
            for _ in 0..2 {
                let mut wire = BytesMut::new();
                encoder.encode(&headers, &mut wire);
                assert_eq!(wire[0] & 0xf0, 0x10);
                assert_eq!(decoder.decode(wire.as_slice())?, headers);
            }
            assert!(matches!(decoder.decode(&[0xbe]), Err(ProtoError::Hpack(_))));
        }
        Ok(())
    }

    #[test]
    fn frame_variants_encode_decode_with_exact_boundaries() -> Result<()> {
        let settings = Http2Settings {
            header_table_size: 128,
            enable_push: false,
            max_concurrent_streams: 64,
            initial_window_size: 1024,
            max_frame_size: 32768,
            max_header_list_size: 8192,
        };
        let frames = vec![
            Http2Frame::Data {
                stream_id: 1,
                end_stream: true,
                data: Bytes::from("body"),
            },
            Http2Frame::Headers {
                stream_id: 1,
                end_stream: false,
                end_headers: true,
                header_block: Bytes::from_static(&[0x82]),
            },
            Http2Frame::Priority {
                stream_id: 3,
                exclusive: true,
                stream_dependency: 1,
                weight: 255,
            },
            Http2Frame::RstStream {
                stream_id: 3,
                error_code: Http2ErrorCode::Cancel,
            },
            Http2Frame::Settings {
                ack: false,
                settings,
            },
            Http2Frame::Settings {
                ack: true,
                settings: Http2Settings::default(),
            },
            Http2Frame::Ping {
                ack: false,
                opaque_data: *b"12345678",
            },
            Http2Frame::Ping {
                ack: true,
                opaque_data: *b"87654321",
            },
            Http2Frame::GoAway {
                last_stream_id: 3,
                error_code: Http2ErrorCode::NoError,
                debug_data: Bytes::from("drain"),
            },
            Http2Frame::WindowUpdate {
                stream_id: 0,
                increment: 0x7fff_ffff,
            },
            Http2Frame::WindowUpdate {
                stream_id: 1,
                increment: 1,
            },
            Http2Frame::Continuation {
                stream_id: 1,
                end_headers: true,
                header_block: Bytes::from_static(&[0x84]),
            },
            Http2Frame::Unknown {
                header: Http2FrameHeader {
                    length: 4,
                    frame_type: Http2FrameType::PushPromise,
                    flags: 4,
                    stream_id: 1,
                },
                payload: Bytes::from_static(&[0, 0, 0, 2]),
            },
            Http2Frame::Unknown {
                header: Http2FrameHeader {
                    length: 3,
                    frame_type: Http2FrameType::Unknown(0xfa),
                    flags: 0xe7,
                    stream_id: 0,
                },
                payload: Bytes::from_static(&[1, 2, 3]),
            },
        ];
        let mut wire = BytesMut::new();
        for frame in &frames {
            encode_frame(frame, &mut wire)?;
        }
        for frame in frames {
            assert_eq!(
                decode_frame(&mut wire, DEFAULT_MAX_FRAME_SIZE)?,
                Some(frame)
            );
        }
        assert!(wire.is_empty());
        Ok(())
    }

    #[test]
    fn padding_priority_and_reserved_wire_bits_are_consumed() -> Result<()> {
        assert_eq!(
            decoded(0, 0x09, 0x8000_0001, &[2, b'a', 0, 0])?,
            Some(Http2Frame::Data {
                stream_id: 1,
                end_stream: true,
                data: Bytes::from("a")
            })
        );
        assert_eq!(
            decoded(1, 0x2d, 1, &[1, 0x80, 0, 0, 3, 255, 0x82, 0])?,
            Some(Http2Frame::Headers {
                stream_id: 1,
                end_stream: true,
                end_headers: true,
                header_block: Bytes::from_static(&[0x82])
            })
        );
        assert_eq!(
            decoded(8, 0, 0, &[0x80, 0, 0, 1])?,
            Some(Http2Frame::WindowUpdate {
                stream_id: 0,
                increment: 1
            })
        );
        assert_eq!(
            decoded(7, 0, 0, &[0x80, 0, 0, 1, 0, 0, 0, 0])?,
            Some(Http2Frame::GoAway {
                last_stream_id: 1,
                error_code: Http2ErrorCode::NoError,
                debug_data: Bytes::new()
            })
        );
        Ok(())
    }
}

mod lifecycle_tests {
    use super::*;

    #[test]
    fn compression_error_permanently_retires_partially_updated_context() {
        let mut decoder = HpackDecoder::default();
        let malformed = [0x40, 1, b'x', 1, b'a', 0x80];
        assert!(matches!(
            decoder.decode(&malformed),
            Err(ProtoError::Hpack(_))
        ));
        for block in [&[0xbe][..], &[0x82], &[]] {
            assert!(matches!(decoder.decode(block), Err(ProtoError::Hpack(_))));
        }
        decoder.set_max_table_size(0);
        assert!(matches!(decoder.decode(&[0x20]), Err(ProtoError::Hpack(_))));
    }

    #[test]
    fn fifo_eviction_and_oversized_insertion_discard_stale_indices() -> Result<()> {
        let mut decoder = HpackDecoder::new(68, 4096);
        for name in *b"xyz" {
            assert_eq!(
                decoder.decode(&[0x40, 1, name, 1, b'a'])?,
                fields(&[(&(name as char).to_string(), "a")])
            );
        }
        assert_eq!(
            decoder.decode(&[0xbe, 0xbf])?,
            fields(&[("z", "a"), ("y", "a")])
        );
        assert!(matches!(decoder.decode(&[0xc0]), Err(ProtoError::Hpack(_))));
        let mut decoder = HpackDecoder::new(34, 4096);
        decoder.decode(&[0x40, 1, b'x', 1, b'a'])?;
        assert_eq!(
            decoder.decode(&[0x40, 2, b'y', b'y', 2, b'b', b'b'])?,
            fields(&[("yy", "bb")])
        );
        assert!(matches!(decoder.decode(&[0xbe]), Err(ProtoError::Hpack(_))));
        Ok(())
    }

    #[test]
    fn encoder_shrink_then_grow_emits_both_updates_and_rebuilds_context() -> Result<()> {
        let mut encoder = HpackEncoder::default();
        let mut decoder = HpackDecoder::default();
        let headers = fields(&[("x", "a")]);
        let mut wire = BytesMut::new();
        encoder.encode(&headers, &mut wire);
        assert_eq!(decoder.decode(wire.as_slice())?, headers);
        encoder.set_max_table_size(0);
        encoder.set_max_table_size(4096);
        wire.clear();
        encoder.encode(&headers, &mut wire);
        assert!(wire.starts_with(&[0x20, 0x3f, 0xe1, 0x1f]));
        assert_eq!(decoder.decode(wire.as_slice())?, headers);
        wire.clear();
        encoder.encode(&headers, &mut wire);
        assert_eq!(wire.as_slice(), &[0xbe]);
        assert_eq!(decoder.decode(wire.as_slice())?, headers);
        Ok(())
    }

    #[test]
    fn decoder_limit_reduction_requires_an_initial_size_update() -> Result<()> {
        let mut decoder = HpackDecoder::default();
        decoder.set_max_table_size(64);
        assert!(matches!(decoder.decode(&[0x82]), Err(ProtoError::Hpack(_))));
        let mut decoder = HpackDecoder::default();
        decoder.set_max_table_size(64);
        assert_eq!(
            decoder.decode(&[0x3f, 0x21, 0x82])?,
            fields(&[(":method", "GET")])
        );
        decoder.set_max_table_size(0);
        decoder.set_max_table_size(4096);
        assert_eq!(
            decoder.decode(&[0x20, 0x3f, 0xe1, 0x1f, 0x82])?,
            fields(&[(":method", "GET")])
        );
        Ok(())
    }

    #[test]
    fn rejected_header_list_still_consumes_later_dynamic_insertions() -> Result<()> {
        let mut decoder = HpackDecoder::new(4096, 40);
        let result = decoder.decode(&[0x40, 1, b'x', 1, b'a', 0x40, 1, b'y', 1, b'b']);
        assert!(matches!(
            result,
            Err(ProtoError::HeaderListTooLarge { size: 68, max: 40 })
        ));
        assert_eq!(decoder.decode(&[0xbe])?, fields(&[("y", "b")]));
        assert_eq!(decoder.decode(&[0xbf])?, fields(&[("x", "a")]));
        Ok(())
    }
}

mod scenario_tests {
    use super::*;

    #[test]
    fn huffman_rejects_eos_overlong_padding_and_non_one_padding() {
        for input in [
            &[0xff][..],
            &[0xff, 0xff, 0xff, 0xff],
            &[0x18],
            &[0x1e],
            &[0x07, 0xff],
        ] {
            assert!(
                matches!(huffman_decode(input), Err(ProtoError::Hpack(_))),
                "accepted {input:02x?}"
            );
        }
    }

    #[test]
    fn hpack_rejects_invalid_indices_integer_overflow_truncation_and_utf8() {
        for block in [
            vec![0x80],
            vec![0xbe],
            vec![0xff, 0],
            vec![0xff],
            vec![0x40],
            vec![0x40, 1],
            vec![0x40, 1, b'x'],
            vec![0x40, 1, b'x', 2, b'a'],
            vec![0x00, 1, 0xff, 0],
            vec![0x00, 1, b'x', 1, 0xff],
            vec![0x00, 1, b'x', 0x81, 0xff],
            vec![0x82, 0x20],
            vec![0x3f, 0xe2, 0x1f],
        ] {
            compression_error(&block);
        }
        let mut overflow = vec![0xff];
        overflow.extend_from_slice(&[0xff; 16]);
        overflow.push(0);
        compression_error(&overflow);
    }

    #[test]
    fn long_literal_lengths_cross_integer_prefix_boundaries() -> Result<()> {
        let headers = vec![("x".repeat(200), "q".repeat(400))];
        let mut encoder = HpackEncoder::new(0);
        let mut decoder = HpackDecoder::new(0, 4096);
        let mut wire = BytesMut::new();
        encoder.encode(&headers, &mut wire);
        assert_eq!(decoder.decode(wire.as_slice())?, headers);
        assert!(matches!(
            HpackDecoder::new(0, 631).decode(wire.as_slice()),
            Err(ProtoError::HeaderListTooLarge {
                size: 632,
                max: 631
            })
        ));
        Ok(())
    }

    #[test]
    fn each_incomplete_frame_is_transactional_and_coalesced_frames_survive() -> Result<()> {
        let frame = Http2Frame::Data {
            stream_id: 1,
            end_stream: true,
            data: Bytes::from("payload"),
        };
        let mut wire = BytesMut::new();
        encode_frame(&frame, &mut wire)?;
        let mut input = BytesMut::new();
        for (index, byte) in wire.iter().enumerate() {
            input.put_u8(*byte);
            let before = input.clone();
            let result = decode_frame(&mut input, DEFAULT_MAX_FRAME_SIZE)?;
            if index + 1 == wire.len() {
                assert_eq!(result, Some(frame.clone()));
                assert!(input.is_empty());
            } else {
                assert_eq!(result, None);
                assert_eq!(input, before);
            }
        }
        let mut unknown = raw(0xee, 0xff, 7, &[1, 2, 3]);
        encode_frame(&frame, &mut unknown)?;
        assert!(matches!(
            decode_frame(&mut unknown, DEFAULT_MAX_FRAME_SIZE)?,
            Some(Http2Frame::Unknown { .. })
        ));
        assert_eq!(
            decode_frame(&mut unknown, DEFAULT_MAX_FRAME_SIZE)?,
            Some(frame)
        );
        assert!(unknown.is_empty());
        for mut invalid in [
            raw(6, 0, 0, &[0; 7]),
            raw(0, 8, 1, &[1]),
            raw(8, 0, 0, &[0; 4]),
        ] {
            let before = invalid.clone();
            assert!(decode_frame(&mut invalid, DEFAULT_MAX_FRAME_SIZE).is_err());
            assert_eq!(invalid, before);
        }
        Ok(())
    }

    #[test]
    fn frame_stream_constraints_and_fixed_payload_lengths_are_enforced() {
        for (kind, payload) in [
            (0, &[][..]),
            (1, &[][..]),
            (2, &[0; 5][..]),
            (3, &[0; 4][..]),
            (5, &[0, 0, 0, 2][..]),
            (9, &[][..]),
        ] {
            connection_error(decoded(kind, 0, 0, payload), Http2ErrorCode::ProtocolError);
        }
        for (kind, payload) in [(4, &[][..]), (6, &[0; 8][..]), (7, &[0; 8][..])] {
            connection_error(decoded(kind, 0, 1, payload), Http2ErrorCode::ProtocolError);
        }
        for (kind, payload) in [
            (2, &[0; 4][..]),
            (3, &[0; 3][..]),
            (4, &[0; 5][..]),
            (6, &[0; 7][..]),
            (6, &[0; 9][..]),
            (7, &[0; 7][..]),
            (8, &[0; 3][..]),
            (5, &[0; 3][..]),
        ] {
            let stream_id = if matches!(kind, 4 | 6 | 7) { 0 } else { 1 };
            assert!(matches!(
                decoded(kind, 0, stream_id, payload),
                Err(ProtoError::Http2ConnectionError {
                    code: Http2ErrorCode::FrameSizeError,
                    ..
                }) | Err(ProtoError::Http2StreamError {
                    code: Http2ErrorCode::FrameSizeError,
                    ..
                })
            ));
        }
        connection_error(decoded(4, 1, 0, &[0; 6]), Http2ErrorCode::FrameSizeError);
    }

    #[test]
    fn settings_values_window_increments_and_frame_limit_report_precise_errors() -> Result<()> {
        connection_error(
            decoded(4, 0, 0, &[0, 2, 0, 0, 0, 2]),
            Http2ErrorCode::ProtocolError,
        );
        connection_error(
            decoded(4, 0, 0, &[0, 4, 0x80, 0, 0, 0]),
            Http2ErrorCode::FlowControlError,
        );
        for value in [16_383_u32, 16_777_216] {
            let mut payload = vec![0, 5];
            payload.extend_from_slice(&value.to_be_bytes());
            connection_error(decoded(4, 0, 0, &payload), Http2ErrorCode::ProtocolError);
        }
        connection_error(decoded(8, 0, 0, &[0; 4]), Http2ErrorCode::ProtocolError);
        assert!(matches!(
            decoded(8, 0, 1, &[0; 4]),
            Err(ProtoError::Http2StreamError {
                stream_id: 1,
                code: Http2ErrorCode::ProtocolError,
                ..
            })
        ));
        for value in [16_384_u32, 16_777_215] {
            let mut payload = vec![0, 5];
            payload.extend_from_slice(&value.to_be_bytes());
            assert!(
                matches!(decoded(4, 0, 0, &payload)?, Some(Http2Frame::Settings { settings, .. }) if settings.max_frame_size == value)
            );
        }
        assert!(matches!(
            decoded(4, 0, 0, &[0, 99, 0xff, 0xff, 0xff, 0xff])?,
            Some(Http2Frame::Settings { .. })
        ));
        let mut oversized = raw(0, 0, 1, &vec![0; DEFAULT_MAX_FRAME_SIZE as usize + 1]);
        connection_error(
            decode_frame(&mut oversized, DEFAULT_MAX_FRAME_SIZE),
            Http2ErrorCode::FrameSizeError,
        );
        Ok(())
    }

    #[test]
    fn malformed_padding_dependencies_and_promised_streams_fail_closed() {
        for (kind, flags, payload) in [
            (0, 8, &[][..]),
            (0, 8, &[1][..]),
            (1, 8, &[2, 0][..]),
            (1, 0x20, &[0; 4][..]),
            (5, 8, &[4, 0, 0, 0, 2][..]),
        ] {
            assert!(decoded(kind, flags, 1, payload).is_err());
        }
        for kind in [1, 2] {
            let flags = if kind == 1 { 0x20 } else { 0 };
            assert!(matches!(
                decoded(kind, flags, 1, &[0, 0, 0, 1, 0]),
                Err(ProtoError::Http2StreamError {
                    stream_id: 1,
                    code: Http2ErrorCode::ProtocolError,
                    ..
                })
            ));
        }
        connection_error(
            decoded(5, 4, 1, &[0, 0, 0, 0]),
            Http2ErrorCode::ProtocolError,
        );
    }

    #[test]
    fn invalid_encodes_leave_existing_output_unchanged() {
        let invalid = [
            Http2Frame::Data {
                stream_id: 0,
                end_stream: false,
                data: Bytes::new(),
            },
            Http2Frame::Data {
                stream_id: 0x8000_0001,
                end_stream: false,
                data: Bytes::new(),
            },
            Http2Frame::Priority {
                stream_id: 1,
                exclusive: false,
                stream_dependency: 1,
                weight: 0,
            },
            Http2Frame::WindowUpdate {
                stream_id: 0,
                increment: 0,
            },
            Http2Frame::WindowUpdate {
                stream_id: 1,
                increment: 0x8000_0000,
            },
            Http2Frame::Settings {
                ack: false,
                settings: Http2Settings {
                    max_frame_size: 1,
                    ..Http2Settings::default()
                },
            },
            Http2Frame::Unknown {
                header: Http2FrameHeader {
                    length: 4,
                    frame_type: Http2FrameType::Unknown(0xee),
                    flags: 0,
                    stream_id: 0,
                },
                payload: Bytes::from("bad"),
            },
        ];
        for frame in invalid {
            let mut output = BytesMut::new();
            output.extend_from_slice(b"preserved");
            assert!(encode_frame(&frame, &mut output).is_err());
            assert_eq!(output.as_slice(), b"preserved");
        }
    }
}

mod e2e_tests {
    use super::*;

    fn transfer(from: &mut Http2Connection, to: &mut Http2Connection) -> Result<()> {
        let mut wire = BytesMut::new();
        from.take_tx_bytes(&mut wire);
        let mut input = BytesMut::new();
        for chunk in wire.chunks(1) {
            input.extend_from_slice(chunk);
            to.feed_bytes(&mut input)?;
        }
        assert!(input.is_empty());
        Ok(())
    }

    fn pump(client: &mut Http2Connection, server: &mut Http2Connection) -> Result<()> {
        for _ in 0..256 {
            transfer(client, server)?;
            transfer(server, client)?;
            if !client.has_tx_bytes() && !server.has_tx_bytes() {
                return Ok(());
            }
        }
        panic!("in-memory HTTP/2 exchange did not settle");
    }

    #[test]
    fn h2c_64_requests_deliver_compressed_headers_and_response_bodies() -> Result<()> {
        let mut client = Http2Connection::client_default();
        let mut server = Http2Connection::server_default();
        pump(&mut client, &mut server)?;
        while client.poll_event().is_some() {}
        while server.poll_event().is_some() {}
        for index in 0..64 {
            let req = Request::get(&format!("http://localhost/compressed/{index}"))?
                .with_header("x-shared-context", "repeated-header-value");
            assert_eq!(client.submit_request(&req)?, index * 2 + 1);
        }
        pump(&mut client, &mut server)?;
        let mut requests = 0;
        while let Some(event) = server.poll_event() {
            let Http2Event::RequestReceived { stream_id, request } = event else {
                panic!("unexpected server event");
            };
            let index = (stream_id - 1) / 2;
            assert_eq!(request.path(), format!("/compressed/{index}"));
            assert_eq!(
                request.header("x-shared-context"),
                Some("repeated-header-value")
            );
            server.submit_response(
                stream_id,
                &Response::ok(format!("response-{index}"))
                    .with_header("x-shared-context", "repeated-response-value"),
            )?;
            requests += 1;
        }
        assert_eq!(requests, 64);
        pump(&mut client, &mut server)?;
        let mut responses = Vec::new();
        while let Some(event) = client.poll_event() {
            let Http2Event::ResponseReceived {
                stream_id,
                response,
            } = event
            else {
                panic!("unexpected client event");
            };
            assert_eq!(
                response.body.as_slice(),
                format!("response-{}", (stream_id - 1) / 2).as_bytes()
            );
            assert_eq!(
                response.header("x-shared-context"),
                Some("repeated-response-value")
            );
            responses.push(stream_id);
        }
        responses.sort_unstable();
        assert_eq!(
            responses,
            (0..64).map(|index| index * 2 + 1).collect::<Vec<_>>()
        );
        assert_eq!(client.active_stream_count(), 0);
        assert_eq!(server.active_stream_count(), 0);
        Ok(())
    }
}
