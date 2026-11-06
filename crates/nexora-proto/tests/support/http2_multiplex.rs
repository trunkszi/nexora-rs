//! Wire and peer helpers shared by the protocol test dimensions.

use super::*;

pub(super) fn drain(connection: &mut Http2Connection) -> BytesMut {
    let mut out = BytesMut::new();
    connection.take_tx_bytes(&mut out);
    out
}
pub(super) fn events(connection: &mut Http2Connection) -> Vec<Http2Event> {
    std::iter::from_fn(|| connection.poll_event()).collect()
}
pub(super) fn feed(
    connection: &mut Http2Connection,
    bytes: &[u8],
    chunk_size: usize,
) -> Result<()> {
    let mut input = BytesMut::new();
    for chunk in bytes.chunks(chunk_size) {
        input.extend_from_slice(chunk);
        connection.feed_bytes(&mut input)?;
    }
    assert!(input.is_empty(), "complete wire input was not consumed");
    Ok(())
}
pub(super) fn inject(connection: &mut Http2Connection, frame: Http2Frame) -> Result<()> {
    let mut wire = BytesMut::new();
    encode_frame(&frame, &mut wire)?;
    feed(connection, wire.as_slice(), 1)
}
pub(super) fn frames(mut wire: BytesMut) -> Result<Vec<Http2Frame>> {
    let mut result = Vec::new();
    while let Some(frame) = decode_frame(&mut wire, DEFAULT_MAX_FRAME_SIZE)? {
        result.push(frame);
    }
    assert!(wire.is_empty(), "outbound frame was truncated");
    Ok(result)
}
pub(super) fn pump(client: &mut Http2Connection, server: &mut Http2Connection) -> Result<()> {
    for _ in 0..512 {
        let outbound = drain(client);
        feed(server, outbound.as_slice(), 7)?;
        let inbound = drain(server);
        feed(client, inbound.as_slice(), 13)?;
        if !client.has_tx_bytes() && !server.has_tx_bytes() {
            return Ok(());
        }
    }
    panic!("HTTP/2 peers did not reach quiescence");
}
pub(super) fn pair(server_config: Http2Config) -> Result<(Http2Connection, Http2Connection)> {
    let mut client = Http2Connection::client_default();
    let mut server = Http2Connection::new(Http2Role::Server, server_config);
    pump(&mut client, &mut server)?;
    assert!(events(&mut client).contains(&Http2Event::SettingsAcknowledged));
    assert!(events(&mut server).contains(&Http2Event::SettingsAcknowledged));
    Ok((client, server))
}
#[rustfmt::skip]
pub(super) fn raw_client(mut settings: Http2Settings) -> Result<Http2Connection> {
    settings.enable_push = false;
    let mut client = Http2Connection::client_default();
    drain(&mut client);
    inject(&mut client, Http2Frame::Settings { ack: false, settings })?;
    assert!(matches!(frames(drain(&mut client))?.as_slice(), [Http2Frame::Settings { ack: true, .. }]));
    Ok(client)
}
pub(super) fn request(index: usize, size: usize) -> Result<Request> {
    Request::post(
        &format!("https://localhost/items/{index}"),
        vec![index as u8; size],
    )
}
pub(super) fn data_bytes(wire: BytesMut) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for frame in frames(wire)? {
        if let Http2Frame::Data { data, .. } = frame {
            result.extend_from_slice(data.as_slice());
        }
    }
    Ok(result)
}
#[rustfmt::skip]
pub(super) fn window(connection: &mut Http2Connection, stream_id: u32, increment: u32) -> Result<()> {
    inject(connection, Http2Frame::WindowUpdate { stream_id, increment })
}
#[rustfmt::skip]
pub(super) fn headers(stream_id: u32, end_stream: bool, end_headers: bool, block: &[u8]) -> Http2Frame {
    Http2Frame::Headers { stream_id, end_stream, end_headers, header_block: Bytes::copy_from_slice(block) }
}
pub(super) fn assert_connection_error(result: Result<()>, expected: Http2ErrorCode) {
    assert!(
        matches!(result, Err(ProtoError::Http2ConnectionError { code, .. }) if code == expected)
    );
}
