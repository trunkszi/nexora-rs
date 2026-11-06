//! Buffer isolation, word boundaries, and malformed protocol records.
use nexora_proto::{
    BytesMut, Headers, HpackDecoder, HpackEncoder, Http1ServerCodec, Result, WebSocketCodec,
    WebSocketConfig, WebSocketMessage, WebSocketRole,
};

fn bytes(data: &[u8]) -> BytesMut {
    let mut out = BytesMut::new();
    out.extend_from_slice(data);
    out
}

#[test]
fn hpack_status_500_uses_static_index() {
    let mut wire = BytesMut::new();
    HpackEncoder::default().encode(&[(":status".into(), "500".into())], &mut wire);
    assert_eq!(wire.as_slice(), &[0x8e]);
}

#[test]
fn hash_case_boundaries_preserve_duplicates() {
    for prefix in 0..=33 {
        for marker in
            (0u8..=255)
                .map(char::from)
                .chain(['\u{03a3}', '\u{0410}', '\u{1f600}', '\u{10ffff}'])
        {
            let name = format!("{}{}Z", "X".repeat(prefix), marker);
            let lower = name.to_ascii_lowercase();
            let mut headers = Headers::new();
            for n in 0..6 {
                headers.append(format!("padding-{n}"), "pad");
            }
            headers.append(&name, "first");
            headers.append(&lower, "second");
            assert_eq!(headers.get(&name.to_ascii_uppercase()), Some("first"));
            assert_eq!(headers.get_all(&lower), ["first", "second"]);
            headers.insert(&name, "replacement");
            assert_eq!(headers.get_all(&lower), ["replacement"]);
            assert_eq!(headers.remove(&lower).as_deref(), Some("replacement"));
            assert!(!headers.contains(&name));
        }
    }
}
#[test]
fn split_resize_preserves_all_other_views() {
    let original: Vec<u8> = (0..33).collect();
    for split in 0..=original.len() {
        for len in [0, 1, 7, 8, 9, 15, 16, 31, 32, 65] {
            let mut all = bytes(&original);
            let mut left = all.split_to(split);
            let frozen = left.clone().freeze();
            let mut expected = original[..split].to_vec();
            expected.resize(len, 0xab);
            left.resize(len, 0xab);
            assert_eq!(left.as_slice(), expected);
            assert_eq!(frozen.as_slice(), &original[..split]);
            assert_eq!(all.as_slice(), &original[split..]);
            all.clear();
            all.extend_from_slice(b"new suffix");
            assert_eq!(left.as_slice(), expected);
            assert_eq!(frozen.as_slice(), &original[..split]);
        }
    }
}
#[test]
fn cr_and_chunk_splits_preserve_framing() -> Result<()> {
    for padding in 0..=24 {
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: host\r\nX-Pad: {}\r\nTransfer-Encoding: \
             chunked\r\n\r\n1;key=\"value\"\r\nx\r\n0\r\nX-Trailer: end\r\n\r\n",
            "a".repeat(padding)
        );
        for split in 0..wire.len() {
            let mut codec = Http1ServerCodec::default();
            let mut input = bytes(&wire.as_bytes()[..split]);
            assert!(codec.decode_request(&mut input)?.is_none());
            assert_eq!(input.as_slice(), &wire.as_bytes()[..split]);
            input.extend_from_slice(&wire.as_bytes()[split..]);
            let decoded = codec.decode_request(&mut input)?.ok_or_else(|| {
                nexora_proto::ProtoError::Http1Protocol("missing chunked request".into())
            })?;
            assert_eq!(decoded.0.body.as_slice(), b"x");
            assert!(input.is_empty());
        }
    }
    for wire in [
        b"GET /\r HTTP/1.1\r\nHost: host\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: host\r\nX: lone\r\r\n\r\n".as_slice(),
    ] {
        assert!(
            Http1ServerCodec::default()
                .decode_request(&mut bytes(wire))
                .is_err()
        );
    }
    Ok(())
}
#[test]
fn websocket_mask_tails_match_wire_rule() {
    let mask = [0x5a, 0xff, 0x02, 0x7e];
    for offset in 0..16 {
        for length in 0..=65 {
            let mut data: Vec<u8> = (0..offset + length).map(|x| x as u8).collect();
            let before = data.clone();
            WebSocketCodec::apply_mask(&mut data[offset..], mask);
            assert_eq!(&data[..offset], &before[..offset]);
            for index in 0..length {
                assert_eq!(
                    data[offset + index],
                    before[offset + index] ^ mask[index & 3]
                );
            }
            WebSocketCodec::apply_mask(&mut data[offset..], mask);
            assert_eq!(data, before);
        }
    }
}
#[test]
fn websocket_extended_lengths_roundtrip() -> Result<()> {
    let config = WebSocketConfig {
        max_frame_size: 70_000,
        max_message_size: 70_000,
    };
    for length in [125, 126, 127, 65_535, 65_536] {
        let payload: Vec<_> = (0..length).map(|n| n as u8).collect();
        let mut wire = BytesMut::new();
        WebSocketCodec::new(WebSocketRole::Server, config)
            .encode_message(&WebSocketMessage::Binary(payload.clone().into()), &mut wire)?;
        assert_eq!(
            wire[1],
            if length < 126 {
                length as u8
            } else if length <= 65_535 {
                126
            } else {
                127
            }
        );
        let mut client = WebSocketCodec::new(WebSocketRole::Client, config);
        let message = client.decode_message(&mut wire)?;
        assert!(
            matches!(message, Some(WebSocketMessage::Binary(data)) if data.as_slice() == payload)
        );
        assert!(wire.is_empty());
    }
    Ok(())
}
#[test]
fn websocket_invalid_close_and_utf8_fail() {
    for payload in [
        vec![0],
        vec![0x03, 0xed],
        vec![0x03, 0xee],
        vec![0x03, 0xf7],
        vec![0x03, 0xe8, 0xff],
        vec![0x13, 0x88],
        vec![0, 1],
    ] {
        let mut wire = bytes(&[0x88, payload.len() as u8]);
        wire.extend_from_slice(&payload);
        assert!(
            WebSocketCodec::client_default()
                .decode_message(&mut wire)
                .is_err()
        );
    }
    for payload in [
        vec![0xc0, 0xaf],
        vec![0xed, 0xa0, 0x80],
        vec![0xf4, 0x90, 0x80, 0x80],
    ] {
        let mut wire = bytes(&[0x81, payload.len() as u8]);
        wire.extend_from_slice(&payload);
        assert!(
            WebSocketCodec::client_default()
                .decode_message(&mut wire)
                .is_err()
        );
    }
}
#[test]
fn fragmented_utf8_survives_control_frames() -> Result<()> {
    let mut codec = WebSocketCodec::client_default();
    let mut first = bytes(&[0x01, 2, 0xf0, 0x9f]);
    assert!(codec.decode_message(&mut first)?.is_none());
    let mut ping = bytes(&[0x89, 1, b'p']);
    assert!(matches!(
        codec.decode_message(&mut ping)?,
        Some(WebSocketMessage::Ping(_))
    ));
    let mut last = bytes(&[0x80, 2, 0x98, 0x80]);
    assert_eq!(
        codec.decode_message(&mut last)?,
        Some(WebSocketMessage::Text("\u{1f600}".into()))
    );
    Ok(())
}
#[test]
fn hpack_limits_and_overflow_are_terminal() {
    for wire in [
        vec![0xff; 32],
        vec![0x80],
        vec![0xff, 0],
        vec![0x00, 0x01],
        vec![0x3f, 0xe2, 0x1f],
        vec![0x82, 0x20],
    ] {
        let mut decoder = HpackDecoder::default();
        assert!(decoder.decode(&wire).is_err(), "accepted {wire:?}");
        assert!(decoder.decode(&[0x82]).is_err());
    }
    assert!(
        HpackDecoder::default()
            .decode(&[0x3f, 0xe1, 0x1f, 0x82])
            .is_ok()
    );
}
