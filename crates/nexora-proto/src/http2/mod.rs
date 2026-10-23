//! Sans-IO HTTP/2 framing, compression, and multiplexed connections.

pub mod connection;
pub mod frame;
pub mod hpack;
pub mod huffman;

use std::collections::BTreeMap;

pub use connection::{Http2Config, Http2Connection, Http2Event, Http2Role};
pub use frame::{
    CLIENT_PREFACE, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE, Http2Frame,
    Http2FrameHeader, Http2FrameType, Http2Settings, MAX_FLOW_CONTROL_WINDOW, decode_frame,
    encode_frame,
};
pub use hpack::{HpackDecoder, HpackEncoder};
pub use huffman::{huffman_decode, huffman_encode, huffman_encoded_len};

use crate::{Http2ErrorCode, ProtoError, Result};

fn connection_error(code: Http2ErrorCode, reason: &str) -> ProtoError {
    ProtoError::Http2ConnectionError {
        code,
        reason: reason.into(),
    }
}

fn stream_error(stream_id: u32, code: Http2ErrorCode, reason: &str) -> ProtoError {
    ProtoError::Http2StreamError {
        stream_id,
        code,
        reason: reason.into(),
    }
}

fn validate_settings(settings: Http2Settings) -> Result<()> {
    if i64::from(settings.initial_window_size) > MAX_FLOW_CONTROL_WINDOW {
        return Err(connection_error(
            Http2ErrorCode::FlowControlError,
            "invalid initial window size",
        ));
    }
    if !(16_384..=16_777_215).contains(&settings.max_frame_size) {
        return Err(connection_error(
            Http2ErrorCode::ProtocolError,
            "invalid maximum frame size",
        ));
    }
    Ok(())
}

#[rustfmt::skip]
fn validate_headers(fields: &[(String, String)], role: Http2Role, trailers: bool, id: u32) -> Result<()> {
    let invalid = || stream_error(id, Http2ErrorCode::ProtocolError, "invalid HTTP/2 message headers");
    let mut regular = false;
    let mut pseudo = BTreeMap::new();
    for (name, value) in fields {
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_uppercase()) || value.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) || value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
            return Err(invalid());
        }
        if name.starts_with(':') {
            if trailers || regular || pseudo.insert(name.as_str(), value.as_str()).is_some() {
                return Err(invalid());
            }
            if !(if role == Http2Role::Server { matches!(name.as_str(), ":method" | ":scheme" | ":path" | ":authority") } else { name == ":status" }) {
                return Err(invalid());
            }
        } else {
            regular = true;
            if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b))
                || matches!(name.as_str(), "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade")
                || (name == "te" && value != "trailers")
                || (trailers && name == "content-length")
            {
                return Err(invalid());
            }
        }
    }
    if trailers {
        return Ok(());
    }
    if role == Http2Role::Server {
        let method = pseudo.get(":method").copied().ok_or_else(invalid)?;
        if method == "CONNECT" {
            if !pseudo.contains_key(":authority") || pseudo.contains_key(":scheme") || pseudo.contains_key(":path") {
                return Err(invalid());
            }
        } else if !matches!(pseudo.get(":scheme").copied(), Some("http" | "https")) || !pseudo.get(":path").is_some_and(|path| path.starts_with('/') || *path == "*") {
            return Err(invalid());
        }
        if !pseudo.get(":authority").is_some_and(|value| !value.is_empty()) && !fields.iter().any(|(name, value)| name == "host" && !value.is_empty()) {
            return Err(invalid());
        }
    } else if !pseudo.get(":status").is_some_and(|status| {
        status.len() == 3 && status.bytes().all(|b| b.is_ascii_digit()) && *status != "101" && status.parse::<u16>().is_ok_and(|status| (100..=599).contains(&status))
    }) {
        return Err(invalid());
    }
    Ok(())
}

#[rustfmt::skip]
fn explicit_push_enabled(bytes: &[u8]) -> bool {
    if bytes.len() < 9 || bytes[3] != 4 || bytes[4] & 1 != 0 {
        return false;
    }
    let length = (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
    bytes.get(9..9 + length).is_some_and(|payload| payload.as_chunks::<6>().0.iter().any(|item| item[0..2] == [0, 2] && item[2..6] == [0, 0, 0, 1]))
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::{Bytes, BytesMut, Request};

    fn take(connection: &mut Http2Connection) -> BytesMut {
        let mut bytes = BytesMut::new();
        connection.take_tx_bytes(&mut bytes);
        bytes
    }

    fn receive(connection: &mut Http2Connection, frame: &Http2Frame) -> Result<()> {
        let mut bytes = BytesMut::new();
        encode_frame(frame, &mut bytes)?;
        connection.feed_bytes(&mut bytes)
    }

    fn client(config: Http2Config) -> Result<Http2Connection> {
        let mut client = Http2Connection::new(Http2Role::Client, config);
        take(&mut client);
        receive(
            &mut client,
            &Http2Frame::Settings {
                ack: false,
                settings: Http2Settings {
                    enable_push: false,
                    ..Http2Settings::default()
                },
            },
        )?;
        take(&mut client);
        Ok(client)
    }

    fn settings(values: &[(u16, u32)]) -> Http2Frame {
        let mut bytes = BytesMut::new();
        for &(id, value) in values {
            bytes.put_u16(id);
            bytes.put_u32(value);
        }
        Http2Frame::Unknown {
            header: Http2FrameHeader {
                length: bytes.len() as u32,
                frame_type: Http2FrameType::Settings,
                flags: 0,
                stream_id: 0,
            },
            payload: bytes.freeze(),
        }
    }

    #[test]
    fn duplicate_settings_preserve_intermediate_table_eviction() -> Result<()> {
        let mut client = client(Http2Config::default())?;
        let request = Request::get("https://localhost/table")?.with_header("x-history", "retained");
        client.submit_request(&request)?;
        take(&mut client);
        receive(&mut client, &settings(&[(1, 0), (1, 4096)]))?;
        client.submit_request(&request)?;
        let mut wire = take(&mut client);
        let mut decoded = None;
        while let Some(frame) = decode_frame(&mut wire, DEFAULT_MAX_FRAME_SIZE)? {
            if let Http2Frame::Headers { header_block, .. } = frame {
                assert_eq!(header_block.first(), Some(&0x20));
                decoded = Some(HpackDecoder::default().decode(header_block.as_slice())?);
            }
        }
        assert!(decoded.is_some_and(|headers| {
            headers
                .iter()
                .any(|(name, value)| name == "x-history" && value == "retained")
        }));
        Ok(())
    }

    #[test]
    fn duplicate_settings_cannot_hide_intermediate_window_overflow() -> Result<()> {
        let mut client = client(Http2Config::default())?;
        let id = client.submit_request(&Request::get("https://localhost/window")?)?;
        take(&mut client);
        receive(
            &mut client,
            &Http2Frame::WindowUpdate {
                stream_id: id,
                increment: 0x7fff_ffff - 65_535,
            },
        )?;
        let result = receive(&mut client, &settings(&[(4, 65_536), (4, 65_535)]));
        assert!(matches!(
            result,
            Err(ProtoError::Http2ConnectionError {
                code: Http2ErrorCode::FlowControlError,
                ..
            })
        ));
        assert_eq!(client.stream_send_window(id), Some(MAX_FLOW_CONTROL_WINDOW));
        let mut wire = take(&mut client);
        assert!(matches!(
            decode_frame(&mut wire, DEFAULT_MAX_FRAME_SIZE)?,
            Some(Http2Frame::GoAway {
                error_code: Http2ErrorCode::FlowControlError,
                ..
            })
        ));
        assert!(wire.is_empty());
        Ok(())
    }

    #[test]
    fn header_limit_rejection_preserves_sibling_compression_context() -> Result<()> {
        let mut client = client(Http2Config {
            local_settings: Http2Settings {
                max_header_list_size: 100,
                ..Http2Settings::default()
            },
            ..Http2Config::default()
        })?;
        let rejected = client.submit_request(&Request::get("https://localhost/large")?)?;
        let sibling = client.submit_request(&Request::get("https://localhost/small")?)?;
        take(&mut client);
        let mut encoder = HpackEncoder::default();
        let mut oversized = BytesMut::new();
        encoder.encode(
            &[
                (":status".into(), "200".into()),
                ("x-history".into(), "retained".into()),
                ("x-padding".into(), "a".repeat(100)),
            ],
            &mut oversized,
        );
        let error = receive(
            &mut client,
            &Http2Frame::Headers {
                stream_id: rejected,
                end_stream: true,
                end_headers: true,
                header_block: oversized.freeze(),
            },
        );
        assert!(
            matches!(error, Err(ProtoError::Http2StreamError { stream_id, code: Http2ErrorCode::EnhanceYourCalm, .. }) if stream_id == rejected)
        );
        assert!(client.poll_event().is_none());
        let mut next = BytesMut::new();
        encoder.encode(
            &[
                (":status".into(), "200".into()),
                ("x-history".into(), "retained".into()),
            ],
            &mut next,
        );
        receive(
            &mut client,
            &Http2Frame::Headers {
                stream_id: sibling,
                end_stream: true,
                end_headers: true,
                header_block: next.freeze(),
            },
        )?;
        assert!(
            matches!(client.poll_event(), Some(Http2Event::ResponseReceived { stream_id, response }) if stream_id == sibling && response.header("x-history") == Some("retained"))
        );
        assert_eq!(client.active_stream_count(), 0);
        Ok(())
    }

    #[test]
    fn malformed_priority_obeys_connection_settings_and_continuation_order() -> Result<()> {
        for awaiting_settings in [true, false] {
            let mut connection = if awaiting_settings {
                Http2Connection::client_default()
            } else {
                client(Http2Config::default())?
            };
            if !awaiting_settings {
                let id = connection.submit_request(&Request::get("https://localhost/headers")?)?;
                receive(
                    &mut connection,
                    &Http2Frame::Headers {
                        stream_id: id,
                        end_stream: false,
                        end_headers: false,
                        header_block: Bytes::new(),
                    },
                )?;
            }
            let mut invalid = BytesMut::new();
            invalid.extend_from_slice(&[0, 0, 4, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
            assert!(matches!(
                connection.feed_bytes(&mut invalid),
                Err(ProtoError::Http2ConnectionError {
                    code: Http2ErrorCode::ProtocolError,
                    ..
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn invalid_outbound_headers_and_lengths_leave_stream_and_wire_unchanged() -> Result<()> {
        let mut client = client(Http2Config::default())?;
        for (name, value) in [
            ("x-space", " leading"),
            ("x-tab", "trailing\t"),
            ("host", "different.example"),
            ("content-length", "1"),
        ] {
            let request = Request::get("https://localhost/validate")?.with_header(name, value);
            assert!(client.submit_request(&request).is_err());
            assert!(!client.has_tx_bytes());
            assert_eq!(client.active_stream_count(), 0);
        }
        assert_eq!(
            client.submit_request(&Request::get("https://localhost/valid")?)?,
            1
        );
        Ok(())
    }

    #[test]
    fn oversized_goaway_does_not_start_draining_on_encoding_failure() -> Result<()> {
        let mut client = client(Http2Config::default())?;
        let result = client.send_goaway(
            0x7fff_ffff,
            Http2ErrorCode::NoError,
            Bytes::from(vec![0; DEFAULT_MAX_FRAME_SIZE as usize - 7]),
        );
        assert!(matches!(
            result,
            Err(ProtoError::Http2ConnectionError {
                code: Http2ErrorCode::FrameSizeError,
                ..
            })
        ));
        assert!(client.can_open_stream());
        assert!(!client.has_tx_bytes());
        assert_eq!(
            client.submit_request(&Request::get("https://localhost/usable")?)?,
            1
        );
        Ok(())
    }
}
