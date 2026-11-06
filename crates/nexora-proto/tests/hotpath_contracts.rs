//! Public header-index and framing contracts across machine-word boundaries.

use nexora_proto::Headers;

#[test]
fn header_index_preserves_case_boundaries() {
    for suffix in [0, 9] {
        for len in 0..=48 {
            for marker in [
                '@', 'A', 'Z', '[', '`', 'a', 'z', '{', '\u{00c0}', '\u{00e0}',
            ] {
                let name = format!("{}{}{}", "X".repeat(len), marker, "Y".repeat(suffix));
                let lower = name.to_ascii_lowercase();
                let mut headers = Headers::with_capacity(12);
                for index in 0..8 {
                    headers.append(format!("padding-{index}"), "other");
                }
                headers.append(&name, "first");
                headers.append(&lower, "second");
                assert_eq!(headers.get(&lower), Some("first"));
                assert_eq!(headers.get(&name.to_ascii_uppercase()), Some("first"));
                assert_eq!(headers.get_all(&lower), ["first", "second"]);
                headers.insert(&lower, "replacement");
                assert_eq!(headers.get_all(&name), ["replacement"]);
                assert_eq!(headers.remove(&name).as_deref(), Some("replacement"));
                assert_eq!(headers.get(&lower), None);
            }
        }
    }
}

#[test]
fn hpack_static_dynamic_indices_roundtrip() -> nexora_proto::Result<()> {
    use nexora_proto::{BytesMut, HpackDecoder, HpackEncoder};
    let fields: Vec<_> = [
        (":method", "GET"),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", "example.test"),
    ]
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .into();
    let mut encoder = HpackEncoder::default();
    let mut decoder = HpackDecoder::default();
    let mut out = BytesMut::new();
    encoder.encode(&fields, &mut out);
    assert_eq!(decoder.decode(&out)?, fields);
    out.clear();
    encoder.encode(&fields, &mut out);
    assert_eq!(out.as_slice(), [0x82, 0x84, 0x87, 0xbe]);
    assert_eq!(decoder.decode(&out)?, fields);
    Ok(())
}

#[test]
fn ping_header_matches_wire_vector() -> nexora_proto::Result<()> {
    use nexora_proto::{BytesMut, Http2Frame, http2::encode_frame};
    let frame = Http2Frame::Ping {
        ack: true,
        opaque_data: *b"12345678",
    };
    let mut out = BytesMut::new();
    encode_frame(&frame, &mut out)?;
    assert_eq!(
        out.as_slice(),
        b"\x00\x00\x08\x06\x01\x00\x00\x00\x0012345678"
    );
    Ok(())
}

#[test]
fn http1_scan_preserves_fragmented_pipeline() -> nexora_proto::Result<()> {
    use nexora_proto::{BytesMut, Http1ServerCodec};
    for padding in 0..32 {
        let first = format!(
            "GET /first HTTP/1.1\r\nHost: example.test\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(padding)
        );
        for split in 0..first.len() {
            let mut codec = Http1ServerCodec::default();
            let mut input = BytesMut::new();
            input.extend_from_slice(&first.as_bytes()[..split]);
            assert!(codec.decode_request(&mut input)?.is_none());
            assert_eq!(input.as_slice(), &first.as_bytes()[..split]);
            input.extend_from_slice(&first.as_bytes()[split..]);
            input.extend_from_slice(b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n");
            let (one, _) = codec.decode_request(&mut input)?.ok_or_else(|| {
                nexora_proto::ProtoError::InvalidHeader("missing complete request".into())
            })?;
            assert_eq!(one.uri.path(), "/first");
            let (two, _) = codec.decode_request(&mut input)?.ok_or_else(|| {
                nexora_proto::ProtoError::InvalidHeader("missing complete request".into())
            })?;
            assert_eq!(two.uri.path(), "/next");
            assert!(input.is_empty());
        }
    }
    Ok(())
}
