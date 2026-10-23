//! Stateless HTTP/2 wire framing, with connection-state checks left to the caller.

use crate::{Bytes, BytesMut, Http2ErrorCode, ProtoError, Result};

pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const DEFAULT_INITIAL_WINDOW_SIZE: i64 = 65_535;
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
pub const MAX_FLOW_CONTROL_WINDOW: i64 = 0x7fff_ffff;
const MAX_FRAME_SIZE: u32 = 0x00ff_ffff;
const STREAM_MASK: u32 = 0x7fff_ffff;

/// Frame types from RFC 9113, including extension type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Http2FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    Unknown(u8),
}

impl Http2FrameType {
    fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Data,
            1 => Self::Headers,
            2 => Self::Priority,
            3 => Self::RstStream,
            4 => Self::Settings,
            5 => Self::PushPromise,
            6 => Self::Ping,
            7 => Self::GoAway,
            8 => Self::WindowUpdate,
            9 => Self::Continuation,
            value => Self::Unknown(value),
        }
    }

    fn as_byte(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Headers => 1,
            Self::Priority => 2,
            Self::RstStream => 3,
            Self::Settings => 4,
            Self::PushPromise => 5,
            Self::Ping => 6,
            Self::GoAway => 7,
            Self::WindowUpdate => 8,
            Self::Continuation => 9,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2FrameHeader {
    pub length: u32,
    pub frame_type: Http2FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

/// SETTINGS values. Omitted wire settings decode to their RFC initial values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Default for Http2Settings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: u32::MAX,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE as u32,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: u32::MAX,
        }
    }
}

/// Decoded frames. PUSH_PROMISE retains its complete wire payload in `Unknown`.
/// Padding and deprecated HEADERS priority fields are consumed during decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2Frame {
    Data {
        stream_id: u32,
        end_stream: bool,
        data: Bytes,
    },
    Headers {
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        header_block: Bytes,
    },
    Priority {
        stream_id: u32,
        exclusive: bool,
        stream_dependency: u32,
        weight: u8,
    },
    RstStream {
        stream_id: u32,
        error_code: Http2ErrorCode,
    },
    Settings {
        ack: bool,
        settings: Http2Settings,
    },
    Ping {
        ack: bool,
        opaque_data: [u8; 8],
    },
    GoAway {
        last_stream_id: u32,
        error_code: Http2ErrorCode,
        debug_data: Bytes,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    Continuation {
        stream_id: u32,
        end_headers: bool,
        header_block: Bytes,
    },
    Unknown {
        header: Http2FrameHeader,
        payload: Bytes,
    },
}

/// Append one frame after validating every encoded field.
///
/// The caller enforces the peer's negotiated frame limit and stream state.
/// An error leaves `out` unchanged. SETTINGS ACK ignores its `settings` field.
///
/// # Errors
/// Returns an HTTP/2 error for invalid stream IDs, payload sizes, settings,
/// priority dependencies, padding, reserved fields, or flow-control increments.
///
/// # Panics
/// Does not panic for any frame value.
pub fn encode_frame(frame: &Http2Frame, out: &mut BytesMut) -> Result<()> {
    let header = encoded_header(frame)?;
    validate_header(header, MAX_FRAME_SIZE)?;
    match frame {
        Http2Frame::Priority {
            stream_id,
            stream_dependency,
            ..
        } => validate_dependency(*stream_id, *stream_dependency)?,
        Http2Frame::Settings {
            ack: false,
            settings,
        } => validate_settings(settings)?,
        Http2Frame::GoAway { last_stream_id, .. } if *last_stream_id > STREAM_MASK => {
            return Err(protocol("last stream ID exceeds 31 bits"));
        }
        Http2Frame::WindowUpdate {
            stream_id,
            increment,
        } => {
            validate_increment(*stream_id, *increment)?;
        }
        Http2Frame::Unknown { payload, .. } => {
            // Known type codes carried as raw frames obey the same wire checks.
            validate_raw_send(header, payload.as_ref())?;
            decode_payload(header, payload.as_ref())?;
        }
        _ => {}
    }
    out.put_u24(header.length);
    out.put_u8(header.frame_type.as_byte());
    out.put_u8(header.flags);
    out.put_u32(header.stream_id);
    match frame {
        Http2Frame::Data { data, .. } => out.extend_from_slice(data.as_ref()),
        Http2Frame::Headers { header_block, .. }
        | Http2Frame::Continuation { header_block, .. } => {
            out.extend_from_slice(header_block.as_ref());
        }
        Http2Frame::Priority {
            exclusive,
            stream_dependency,
            weight,
            ..
        } => {
            out.put_u32(*stream_dependency | (u32::from(*exclusive) << 31));
            out.put_u8(*weight);
        }
        Http2Frame::RstStream { error_code, .. } => out.put_u32(error_code.as_u32()),
        Http2Frame::Settings {
            ack: false,
            settings,
        } => {
            for (id, value) in [
                (1, settings.header_table_size),
                (2, u32::from(settings.enable_push)),
                (3, settings.max_concurrent_streams),
                (4, settings.initial_window_size),
                (5, settings.max_frame_size),
                (6, settings.max_header_list_size),
            ] {
                out.put_u16(id);
                out.put_u32(value);
            }
        }
        Http2Frame::Settings { ack: true, .. } => {}
        Http2Frame::Ping { opaque_data, .. } => out.extend_from_slice(opaque_data),
        Http2Frame::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            out.put_u32(*last_stream_id);
            out.put_u32(error_code.as_u32());
            out.extend_from_slice(debug_data.as_ref());
        }
        Http2Frame::WindowUpdate { increment, .. } => out.put_u32(*increment),
        Http2Frame::Unknown { payload, .. } => out.extend_from_slice(payload.as_ref()),
    }
    Ok(())
}

/// Decode and consume one complete frame, retaining all trailing bytes.
///
/// Incomplete frames return `Ok(None)` without consuming input. Invalid frames
/// also leave input unchanged. Reserved bits and unrecognized flags are ignored.
/// The caller checks stream state, continuation ordering, and endpoint roles.
///
/// # Errors
/// Returns an HTTP/2 connection or stream error for malformed frames or payloads
/// larger than `max_frame_size` (or the 24-bit wire limit).
///
/// # Panics
/// Does not panic for any input buffer or frame limit.
pub fn decode_frame(src: &mut BytesMut, max_frame_size: u32) -> Result<Option<Http2Frame>> {
    let bytes = src.as_slice();
    if bytes.len() < 9 {
        return Ok(None);
    }
    let header = Http2FrameHeader {
        length: (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]),
        frame_type: Http2FrameType::from_byte(bytes[3]),
        flags: bytes[4],
        stream_id: read_u32(&bytes[5..9]) & STREAM_MASK,
    };
    validate_header(header, max_frame_size.min(MAX_FRAME_SIZE))?;
    let end = 9 + header.length as usize;
    if bytes.len() < end {
        return Ok(None);
    }
    let frame = decode_payload(header, &bytes[9..end])?;
    src.advance(end);
    Ok(Some(frame))
}

fn validate_raw_send(header: Http2FrameHeader, payload: &[u8]) -> Result<()> {
    let allowed_flags = match header.frame_type {
        Http2FrameType::Data => 0x09,
        Http2FrameType::Headers => 0x2d,
        Http2FrameType::Settings | Http2FrameType::Ping => 0x01,
        Http2FrameType::PushPromise => 0x0c,
        Http2FrameType::Continuation => 0x04,
        Http2FrameType::Unknown(_) => 0xff,
        _ => 0,
    };
    if header.flags & !allowed_flags != 0 {
        return Err(protocol("unused flags must be unset when sending"));
    }
    if matches!(
        header.frame_type,
        Http2FrameType::GoAway | Http2FrameType::WindowUpdate
    ) && read_u32(payload) & !STREAM_MASK != 0
    {
        return Err(protocol("reserved payload bits must be unset when sending"));
    }
    if header.frame_type == Http2FrameType::PushPromise {
        let block = unpadded(payload, header.flags & 8 != 0)?;
        if block.len() >= 4 && read_u32(block) & !STREAM_MASK != 0 {
            return Err(protocol(
                "reserved promised stream bit must be unset when sending",
            ));
        }
    }
    Ok(())
}

fn encoded_header(frame: &Http2Frame) -> Result<Http2FrameHeader> {
    let (length, frame_type, flags, stream_id) = match frame {
        Http2Frame::Data {
            stream_id,
            end_stream,
            data,
        } => (
            data.len(),
            Http2FrameType::Data,
            u8::from(*end_stream),
            *stream_id,
        ),
        Http2Frame::Headers {
            stream_id,
            end_stream,
            end_headers,
            header_block,
        } => (
            header_block.len(),
            Http2FrameType::Headers,
            u8::from(*end_stream) | (u8::from(*end_headers) << 2),
            *stream_id,
        ),
        Http2Frame::Priority { stream_id, .. } => (5, Http2FrameType::Priority, 0, *stream_id),
        Http2Frame::RstStream { stream_id, .. } => (4, Http2FrameType::RstStream, 0, *stream_id),
        Http2Frame::Settings { ack, .. } => (
            if *ack { 0 } else { 36 },
            Http2FrameType::Settings,
            u8::from(*ack),
            0,
        ),
        Http2Frame::Ping { ack, .. } => (8, Http2FrameType::Ping, u8::from(*ack), 0),
        Http2Frame::GoAway { debug_data, .. } => (
            debug_data
                .len()
                .checked_add(8)
                .ok_or_else(|| frame_size("GOAWAY too large"))?,
            Http2FrameType::GoAway,
            0,
            0,
        ),
        Http2Frame::WindowUpdate { stream_id, .. } => {
            (4, Http2FrameType::WindowUpdate, 0, *stream_id)
        }
        Http2Frame::Continuation {
            stream_id,
            end_headers,
            header_block,
        } => (
            header_block.len(),
            Http2FrameType::Continuation,
            u8::from(*end_headers) << 2,
            *stream_id,
        ),
        Http2Frame::Unknown { header, payload } => {
            if header.length as usize != payload.len() {
                return Err(frame_size("raw frame length differs from payload"));
            }
            (
                payload.len(),
                Http2FrameType::from_byte(header.frame_type.as_byte()),
                header.flags,
                header.stream_id,
            )
        }
    };
    if length > MAX_FRAME_SIZE as usize {
        return Err(frame_size("payload exceeds the 24-bit frame size"));
    }
    if stream_id > STREAM_MASK {
        return Err(protocol("stream ID exceeds 31 bits"));
    }
    Ok(Http2FrameHeader {
        length: length as u32,
        frame_type,
        flags,
        stream_id,
    })
}

fn validate_header(header: Http2FrameHeader, max_frame_size: u32) -> Result<()> {
    if header.length > max_frame_size {
        return Err(frame_size("payload exceeds maximum frame size"));
    }
    match header.frame_type {
        Http2FrameType::Settings | Http2FrameType::Ping | Http2FrameType::GoAway => {
            if header.stream_id != 0 {
                return Err(protocol("connection frame uses a nonzero stream ID"));
            }
        }
        Http2FrameType::Data
        | Http2FrameType::Headers
        | Http2FrameType::Priority
        | Http2FrameType::RstStream
        | Http2FrameType::PushPromise
        | Http2FrameType::Continuation => {
            if header.stream_id == 0 {
                return Err(protocol("stream frame uses stream ID zero"));
            }
        }
        Http2FrameType::WindowUpdate | Http2FrameType::Unknown(_) => {}
    }
    let invalid_length = match header.frame_type {
        Http2FrameType::Priority => header.length != 5,
        Http2FrameType::RstStream | Http2FrameType::WindowUpdate => header.length != 4,
        Http2FrameType::Settings => {
            !header.length.is_multiple_of(6) || (header.flags & 1 != 0 && header.length != 0)
        }
        Http2FrameType::Ping => header.length != 8,
        Http2FrameType::GoAway => header.length < 8,
        Http2FrameType::PushPromise => header.length < 4 + u32::from(header.flags & 8 != 0),
        Http2FrameType::Headers => {
            header.length
                < u32::from(header.flags & 8 != 0) + if header.flags & 0x20 != 0 { 5 } else { 0 }
        }
        Http2FrameType::Data => header.flags & 8 != 0 && header.length == 0,
        _ => false,
    };
    if invalid_length {
        if header.frame_type == Http2FrameType::Priority {
            return Err(stream_error(
                header.stream_id,
                Http2ErrorCode::FrameSizeError,
                "PRIORITY payload must be five octets",
            ));
        }
        return Err(frame_size("invalid payload length for frame type"));
    }
    Ok(())
}

fn decode_payload(header: Http2FrameHeader, payload: &[u8]) -> Result<Http2Frame> {
    let stream_id = header.stream_id;
    let flag = |mask| header.flags & mask != 0;
    Ok(match header.frame_type {
        Http2FrameType::Data => Http2Frame::Data {
            stream_id,
            end_stream: flag(1),
            data: Bytes::copy_from_slice(unpadded(payload, flag(8))?),
        },
        Http2FrameType::Headers => {
            let mut block = unpadded(payload, flag(8))?;
            if flag(0x20) {
                if block.len() < 5 {
                    return Err(frame_size("truncated HEADERS priority fields"));
                }
                validate_dependency(stream_id, read_u32(&block[..4]) & STREAM_MASK)?;
                block = &block[5..];
            }
            Http2Frame::Headers {
                stream_id,
                end_stream: flag(1),
                end_headers: flag(4),
                header_block: Bytes::copy_from_slice(block),
            }
        }
        Http2FrameType::Priority => {
            let dependency = read_u32(&payload[..4]);
            validate_dependency(stream_id, dependency & STREAM_MASK)?;
            Http2Frame::Priority {
                stream_id,
                exclusive: dependency & !STREAM_MASK != 0,
                stream_dependency: dependency & STREAM_MASK,
                weight: payload[4],
            }
        }
        Http2FrameType::RstStream => Http2Frame::RstStream {
            stream_id,
            error_code: Http2ErrorCode::from_u32(read_u32(payload)),
        },
        Http2FrameType::Settings => {
            let mut settings = Http2Settings::default();
            for pair in payload.as_chunks::<6>().0 {
                let id = u16::from_be_bytes([pair[0], pair[1]]);
                let value = read_u32(&pair[2..]);
                match id {
                    1 => settings.header_table_size = value,
                    2 => {
                        if value > 1 {
                            return Err(protocol("ENABLE_PUSH must be zero or one"));
                        }
                        settings.enable_push = value != 0;
                    }
                    3 => settings.max_concurrent_streams = value,
                    4 => settings.initial_window_size = value,
                    5 => settings.max_frame_size = value,
                    6 => settings.max_header_list_size = value,
                    _ => {}
                }
                // Each occurrence must be valid, including overwritten settings.
                validate_settings(&settings)?;
            }
            Http2Frame::Settings {
                ack: flag(1),
                settings,
            }
        }
        Http2FrameType::PushPromise => {
            let block = unpadded(payload, flag(8))?;
            if block.len() < 4 {
                return Err(frame_size("truncated promised stream ID"));
            }
            let promised_id = read_u32(&block[..4]) & STREAM_MASK;
            if promised_id == 0 || !promised_id.is_multiple_of(2) {
                return Err(protocol("promised stream ID must be nonzero and even"));
            }
            Http2Frame::Unknown {
                header,
                payload: Bytes::copy_from_slice(payload),
            }
        }
        Http2FrameType::Ping => {
            let mut opaque_data = [0; 8];
            opaque_data.copy_from_slice(payload);
            Http2Frame::Ping {
                ack: flag(1),
                opaque_data,
            }
        }
        Http2FrameType::GoAway => Http2Frame::GoAway {
            last_stream_id: read_u32(&payload[..4]) & STREAM_MASK,
            error_code: Http2ErrorCode::from_u32(read_u32(&payload[4..8])),
            debug_data: Bytes::copy_from_slice(&payload[8..]),
        },
        Http2FrameType::WindowUpdate => {
            let increment = read_u32(payload) & STREAM_MASK;
            validate_increment(stream_id, increment)?;
            Http2Frame::WindowUpdate {
                stream_id,
                increment,
            }
        }
        Http2FrameType::Continuation => Http2Frame::Continuation {
            stream_id,
            end_headers: flag(4),
            header_block: Bytes::copy_from_slice(payload),
        },
        Http2FrameType::Unknown(_) => Http2Frame::Unknown {
            header,
            payload: Bytes::copy_from_slice(payload),
        },
    })
}

fn unpadded(payload: &[u8], padded: bool) -> Result<&[u8]> {
    if !padded {
        return Ok(payload);
    }
    let Some(&padding) = payload.first() else {
        return Err(frame_size("missing padding length"));
    };
    if usize::from(padding) >= payload.len() {
        return Err(protocol("padding exceeds frame payload"));
    }
    let end = payload.len() - usize::from(padding);
    if payload[end..].iter().any(|&byte| byte != 0) {
        return Err(protocol("padding octets must be zero"));
    }
    Ok(&payload[1..end])
}

fn validate_settings(settings: &Http2Settings) -> Result<()> {
    if settings.initial_window_size > STREAM_MASK {
        return Err(connection_error(
            Http2ErrorCode::FlowControlError,
            "INITIAL_WINDOW_SIZE exceeds the flow-control window limit",
        ));
    }
    if !(DEFAULT_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&settings.max_frame_size) {
        return Err(protocol("MAX_FRAME_SIZE is outside its permitted range"));
    }
    Ok(())
}

fn validate_dependency(stream_id: u32, dependency: u32) -> Result<()> {
    if dependency > STREAM_MASK {
        return Err(protocol("stream dependency exceeds 31 bits"));
    }
    if stream_id == dependency {
        return Err(stream_error(
            stream_id,
            Http2ErrorCode::ProtocolError,
            "stream cannot depend on itself",
        ));
    }
    Ok(())
}

fn validate_increment(stream_id: u32, increment: u32) -> Result<()> {
    if increment == 0 || increment > STREAM_MASK {
        if stream_id != 0 {
            return Err(stream_error(
                stream_id,
                Http2ErrorCode::ProtocolError,
                "WINDOW_UPDATE increment must be in 1..=2^31-1",
            ));
        }
        return Err(protocol("WINDOW_UPDATE increment must be in 1..=2^31-1"));
    }
    Ok(())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn connection_error(code: Http2ErrorCode, reason: &str) -> ProtoError {
    ProtoError::Http2ConnectionError {
        code,
        reason: reason.to_owned(),
    }
}

fn stream_error(stream_id: u32, code: Http2ErrorCode, reason: &str) -> ProtoError {
    ProtoError::Http2StreamError {
        stream_id,
        code,
        reason: reason.to_owned(),
    }
}

fn protocol(reason: &str) -> ProtoError {
    connection_error(Http2ErrorCode::ProtocolError, reason)
}

fn frame_size(reason: &str) -> ProtoError {
    connection_error(Http2ErrorCode::FrameSizeError, reason)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn scenario_raw_send_flags_and_reserved_bits_preserve_output_on_error() -> Result<()> {
        for (frame_type, flags, stream_id, payload) in [
            (Http2FrameType::Data, 0x80, 1, &b"x"[..]),
            (Http2FrameType::Ping, 0x80, 0, &[0; 8][..]),
            (Http2FrameType::WindowUpdate, 0, 0, &[0x80, 0, 0, 1][..]),
            (
                Http2FrameType::GoAway,
                0,
                0,
                &[0x80, 0, 0, 1, 0, 0, 0, 0][..],
            ),
            (Http2FrameType::PushPromise, 4, 1, &[0x80, 0, 0, 2][..]),
            (
                Http2FrameType::PushPromise,
                0x0c,
                1,
                &[0, 0x80, 0, 0, 2][..],
            ),
        ] {
            let header = Http2FrameHeader {
                length: payload.len() as u32,
                frame_type,
                flags,
                stream_id,
            };
            let frame = Http2Frame::Unknown {
                header,
                payload: Bytes::copy_from_slice(payload),
            };
            let mut output = BytesMut::new();
            output.extend_from_slice(b"existing");
            assert!(matches!(
                encode_frame(&frame, &mut output),
                Err(ProtoError::Http2ConnectionError {
                    code: Http2ErrorCode::ProtocolError,
                    ..
                })
            ));
            assert_eq!(output.as_slice(), b"existing");

            // Reserved bits and unused flags are ignored only on receipt.
            let mut wire = BytesMut::new();
            wire.put_u24(header.length);
            wire.put_u8(header.frame_type.as_byte());
            wire.put_u8(header.flags);
            wire.put_u32(header.stream_id);
            wire.extend_from_slice(payload);
            assert!(decode_frame(&mut wire, DEFAULT_MAX_FRAME_SIZE)?.is_some());
            assert!(wire.is_empty());
        }
        Ok(())
    }
}
