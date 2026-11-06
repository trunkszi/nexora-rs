//! Protocol target and tunnel semantics at public codec seams.
use nexora_proto::{
    Bytes, BytesMut, HpackDecoder, HpackEncoder, Http1ClientCodec, Http1KeepAlive, Http2Connection,
    Http2Event, Method, Request, Result,
    http2::{
        CLIENT_PREFACE, DEFAULT_MAX_FRAME_SIZE, Http2Frame, Http2Settings, decode_frame,
        encode_frame,
    },
};

fn bytes(input: &[u8]) -> BytesMut {
    let mut out = BytesMut::new();
    out.extend_from_slice(input);
    out
}
fn request_wire(fields: &[(&str, &str)]) -> Result<BytesMut> {
    let mut wire = bytes(CLIENT_PREFACE);
    encode_frame(
        &Http2Frame::Settings {
            ack: false,
            settings: Http2Settings {
                enable_push: false,
                ..Http2Settings::default()
            },
        },
        &mut wire,
    )?;
    let mut block = BytesMut::new();
    HpackEncoder::default().encode(
        &fields
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect::<Vec<_>>(),
        &mut block,
    );
    encode_frame(
        &Http2Frame::Headers {
            stream_id: 1,
            end_stream: true,
            end_headers: true,
            header_block: block.freeze(),
        },
        &mut wire,
    )?;
    Ok(wire)
}
#[test]
fn connect_ignores_response_body_framing() -> Result<()> {
    let mut wire = bytes(b"HTTP/1.1 200 Established\r\nContent-Length: nonsense\r\nTransfer-Encoding: chunked\r\n\r\ntunnel");
    let decoded = Http1ClientCodec::default().decode_response(&mut wire, Method::Connect)?;
    let (response, state) =
        decoded.ok_or_else(|| nexora_proto::ProtoError::Http1Protocol("missing tunnel".into()))?;
    assert_eq!(state, Http1KeepAlive::Upgrade);
    assert!(response.body.is_empty());
    assert_eq!(wire.as_slice(), b"tunnel");
    Ok(())
}
#[test]
fn h2_rejects_malformed_target_components() -> Result<()> {
    for (authority, path) in [
        ("host/path", "/ok"),
        ("host?query", "/ok"),
        ("host#fragment", "/ok"),
        ("host", "/ok#fragment"),
    ] {
        let mut server = Http2Connection::server_default();
        let result = server.feed_bytes(&mut request_wire(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":authority", authority),
            (":path", path),
        ])?);
        assert!(
            result.is_err(),
            "accepted malformed authority/path: {authority:?} {path:?}"
        );
        assert!(server.poll_event().is_none());
    }
    Ok(())
}
#[test]
fn h2_options_preserves_asterisk_target() -> Result<()> {
    let mut server = Http2Connection::server_default();
    server.feed_bytes(&mut request_wire(&[
        (":method", "OPTIONS"),
        (":scheme", "http"),
        (":authority", "host"),
        (":path", "*"),
    ])?)?;
    let Some(Http2Event::RequestReceived { request, .. }) = server.poll_event() else {
        return Err(nexora_proto::ProtoError::Http1Protocol(
            "missing OPTIONS request".into(),
        ));
    };
    assert_eq!(request.uri.host(), "host");
    assert_eq!(request.uri.path(), "/*");
    let mut client = Http2Connection::client_default();
    client.submit_request(&request)?;
    let mut wire = BytesMut::new();
    client.take_tx_bytes(&mut wire);
    wire.advance(CLIENT_PREFACE.len());
    let mut decoder = HpackDecoder::default();
    while let Some(frame) = decode_frame(&mut wire, DEFAULT_MAX_FRAME_SIZE)? {
        if let Http2Frame::Headers { header_block, .. } = frame {
            let fields = decoder.decode(&header_block)?;
            assert!(fields.iter().any(|(n, v)| n == ":path" && v == "*"));
        }
    }
    Ok(())
}
#[test]
fn h2_connect_keeps_destination_port() -> Result<()> {
    let mut client = Http2Connection::client_default();
    let request = Request::new(Method::Connect, nexora_proto::Uri::parse("https://host/")?);
    client.submit_request(&request)?;
    let mut wire = BytesMut::new();
    client.take_tx_bytes(&mut wire);
    let mut server = Http2Connection::server_default();
    server.feed_bytes(&mut wire)?;
    let Some(Http2Event::RequestReceived { request, .. }) = server.poll_event() else {
        return Err(nexora_proto::ProtoError::Http1Protocol(
            "missing CONNECT request".into(),
        ));
    };
    assert_eq!(request.uri.host(), "host");
    assert_eq!(request.uri.port(), 443, "CONNECT lost the destination port");
    assert_eq!(request.body, Bytes::new());
    Ok(())
}

#[test]
fn h2_reset_content_rejects_body() -> Result<()> {
    let mut server = Http2Connection::server_default();
    server.feed_bytes(&mut request_wire(&[
        (":method", "GET"),
        (":scheme", "http"),
        (":authority", "host"),
        (":path", "/"),
    ])?)?;
    assert!(matches!(
        server.poll_event(),
        Some(Http2Event::RequestReceived { .. })
    ));
    let mut ignored = BytesMut::new();
    server.take_tx_bytes(&mut ignored);
    let response =
        nexora_proto::Response::new(nexora_proto::StatusCode::new(205)?).with_body("forbidden");
    assert!(
        server.submit_response(1, &response).is_err(),
        "encoded content forbidden for 205"
    );
    assert!(
        !server.has_tx_bytes(),
        "rejected response modified wire output"
    );
    Ok(())
}
