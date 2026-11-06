//! Protocol-seam tests for the WebSocket client.

use nexora::{Error, Result};
use nexora_proto::{
    Bytes, BytesMut, Http1ClientCodec, Http1KeepAlive, Method, WebSocketCodec, WebSocketConfig,
    WebSocketHandshake, WebSocketMessage, WebSocketOpcode, WebSocketRole,
};

/// Builds one unmasked server frame with a short payload.
fn frame(fin: bool, opcode: WebSocketOpcode, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mut bytes = Vec::with_capacity(2 + payload.len());
    bytes.push((if fin { 0x80 } else { 0 }) | opcode as u8);
    bytes.push(payload.len() as u8);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn upgrade_keeps_trailing_bytes_for_the_websocket_codec() -> Result<()> {
    let key = WebSocketHandshake::generate_key(11);
    let accept = WebSocketHandshake::compute_accept_key(&key);
    let mut wire = BytesMut::new();
    wire.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    wire.extend_from_slice(b"upgrade: websocket\r\nconnection: Upgrade\r\n");
    wire.extend_from_slice(format!("sec-websocket-accept: {accept}\r\n\r\n").as_bytes());
    wire.extend_from_slice(&frame(true, WebSocketOpcode::Text, b"hi"));

    let mut http = Http1ClientCodec::default();
    let (response, keep_alive) = match http.decode_response(&mut wire, Method::Get)? {
        Some(decoded) => decoded,
        None => {
            return Err(Error::InvalidState(String::from(
                "the complete upgrade response was not decoded",
            )));
        }
    };
    assert_eq!(keep_alive, Http1KeepAlive::Upgrade);
    WebSocketHandshake::validate_upgrade_response(&response, &key)?;
    assert_eq!(
        wire.as_slice(),
        &frame(true, WebSocketOpcode::Text, b"hi")[..]
    );

    let mut websocket = WebSocketCodec::new(WebSocketRole::Client, WebSocketConfig::default());
    assert_eq!(
        websocket.decode_message(&mut wire)?,
        Some(WebSocketMessage::Text(String::from("hi")))
    );
    assert!(wire.is_empty());
    Ok(())
}

#[test]
fn client_frames_are_masked() -> Result<()> {
    let payload = b"masked payload";
    let mut websocket = WebSocketCodec::new(WebSocketRole::Client, WebSocketConfig::default());
    let mut wire = BytesMut::new();
    websocket.encode_message(
        &WebSocketMessage::Binary(Bytes::copy_from_slice(payload)),
        &mut wire,
    )?;
    let bytes = wire.as_slice();
    assert_eq!(bytes[0] & 0x0f, WebSocketOpcode::Binary as u8);
    assert_ne!(bytes[1] & 0x80, 0, "client frames must set the mask bit");
    let mask = [bytes[2], bytes[3], bytes[4], bytes[5]];
    let unmasked: Vec<u8> = bytes[6..]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % 4])
        .collect();
    assert_eq!(unmasked, payload);
    Ok(())
}

#[test]
fn fragmented_text_reassembles_around_interleaved_ping() -> Result<()> {
    let mut wire = BytesMut::new();
    wire.extend_from_slice(&frame(false, WebSocketOpcode::Text, b"Hel"));
    wire.extend_from_slice(&frame(true, WebSocketOpcode::Ping, b"p"));
    wire.extend_from_slice(&frame(true, WebSocketOpcode::Continuation, b"lo"));

    let mut websocket = WebSocketCodec::new(WebSocketRole::Client, WebSocketConfig::default());
    assert_eq!(
        websocket.decode_message(&mut wire)?,
        Some(WebSocketMessage::Ping(Bytes::from_static(b"p")))
    );
    assert_eq!(
        websocket.decode_message(&mut wire)?,
        Some(WebSocketMessage::Text(String::from("Hello")))
    );
    Ok(())
}

#[test]
fn masked_server_frames_and_oversized_frames_are_rejected() -> Result<()> {
    let mut masked = BytesMut::new();
    masked.extend_from_slice(&[0x81, 0x81, 0, 0, 0, 0, b'x']);
    let mut websocket = WebSocketCodec::new(WebSocketRole::Client, WebSocketConfig::default());
    assert!(websocket.decode_message(&mut masked).is_err());

    let mut oversized = BytesMut::new();
    oversized.extend_from_slice(&[0x82, 127]);
    oversized.extend_from_slice(&2_000_000_u64.to_be_bytes());
    let mut websocket = WebSocketCodec::new(WebSocketRole::Client, WebSocketConfig::default());
    assert!(websocket.decode_message(&mut oversized).is_err());
    Ok(())
}
