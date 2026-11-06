//! Invalid peer messages must fail their stream without delivering a response.
use nexora_proto::{
    Bytes, BytesMut, HpackEncoder, Http2Connection, Http2ErrorCode, Http2Event, ProtoError,
    Request, Result,
    http2::{Http2Frame, Http2Settings, encode_frame},
};

fn inject(connection: &mut Http2Connection, frame: Http2Frame) -> Result<()> {
    let mut wire = BytesMut::new();
    encode_frame(&frame, &mut wire)?;
    connection.feed_bytes(&mut wire)
}
fn client() -> Result<Http2Connection> {
    let mut client = Http2Connection::client_default();
    inject(
        &mut client,
        Http2Frame::Settings {
            ack: false,
            settings: Http2Settings {
                enable_push: false,
                ..Http2Settings::default()
            },
        },
    )?;
    Ok(client)
}
fn response(
    encoder: &mut HpackEncoder,
    stream_id: u32,
    fields: &[(&str, &str)],
    end: bool,
) -> Http2Frame {
    let mut block = BytesMut::new();
    encoder.encode(
        &fields
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<Vec<_>>(),
        &mut block,
    );
    Http2Frame::Headers {
        stream_id,
        end_stream: end,
        end_headers: true,
        header_block: block.freeze(),
    }
}
fn protocol_error(result: Result<()>, id: u32) {
    assert!(
        matches!(result, Err(ProtoError::Http2StreamError { stream_id, code: Http2ErrorCode::ProtocolError, .. }) if stream_id == id)
    );
}
#[test]
fn reset_content_rejects_received_body() -> Result<()> {
    for fields in [
        vec![(":status", "205")],
        vec![(":status", "205"), ("content-length", "1")],
    ] {
        let mut client = client()?;
        let id = client.submit_request(&Request::get("https://host/reset")?)?;
        let mut encoder = HpackEncoder::default();
        inject(&mut client, response(&mut encoder, id, &fields, false))?;
        protocol_error(
            inject(
                &mut client,
                Http2Frame::Data {
                    stream_id: id,
                    end_stream: true,
                    data: Bytes::from_static(b"x"),
                },
            ),
            id,
        );
        assert!(client.poll_event().is_none());
        let next = client.submit_request(&Request::get("https://host/next")?)?;
        inject(
            &mut client,
            response(
                &mut encoder,
                next,
                &[(":status", "205"), ("content-length", "0")],
                true,
            ),
        )?;
        assert!(
            matches!(client.poll_event(), Some(Http2Event::ResponseReceived { stream_id, response })
            if stream_id == next && response.status.as_u16() == 205 && response.body.is_empty())
        );
    }
    Ok(())
}

#[test]
fn reset_content_empty_length_boundaries() -> Result<()> {
    for length in [None, Some("0"), Some("1"), Some("18446744073709551616")] {
        let mut client = client()?;
        let id = client.submit_request(&Request::get("https://host/reset")?)?;
        let mut fields = vec![(":status", "205")];
        if let Some(length) = length {
            fields.push(("content-length", length));
        }
        let mut encoder = HpackEncoder::default();
        let result = inject(&mut client, response(&mut encoder, id, &fields, true));
        if matches!(length, None | Some("0")) {
            result?;
            assert!(
                matches!(client.poll_event(), Some(Http2Event::ResponseReceived { response, .. })
                if response.status.as_u16() == 205 && response.body.is_empty())
            );
        } else {
            protocol_error(result, id);
            assert!(client.poll_event().is_none());
        }
    }
    Ok(())
}
