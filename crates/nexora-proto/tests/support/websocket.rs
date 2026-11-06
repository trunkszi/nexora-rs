//! Wire and peer helpers shared by the protocol test dimensions.

use super::*;

pub(super) fn buffer(bytes: &[u8]) -> BytesMut {
    let mut result = BytesMut::new();
    result.extend_from_slice(bytes);
    result
}

// This independent wire builder lets decoder tests detect encoder/decoder agreement bugs.
pub(super) fn wire(fin: bool, opcode: u8, payload: &[u8], masked: bool) -> BytesMut {
    let mut out = BytesMut::new();
    out.put_u8(if fin { 0x80 | opcode } else { opcode });
    let flag = if masked { 0x80 } else { 0 };
    match payload.len() {
        0..=125 => out.put_u8(flag | payload.len() as u8),
        126..=65535 => {
            out.put_u8(flag | 126);
            out.put_u16(payload.len() as u16);
        }
        _ => {
            out.put_u8(flag | 127);
            out.put_u64(payload.len() as u64);
        }
    }
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    if masked {
        out.extend_from_slice(&mask);
    }
    for (index, byte) in payload.iter().enumerate() {
        out.put_u8(if masked {
            byte ^ mask[index % 4]
        } else {
            *byte
        });
    }
    out
}

pub(super) fn frame(fin: bool, opcode: WebSocketOpcode, bytes: &[u8]) -> WebSocketFrame {
    WebSocketFrame {
        fin,
        opcode,
        payload: Bytes::copy_from_slice(bytes),
    }
}

pub(super) fn decode_unmasked(
    fin: bool,
    opcode: u8,
    payload: &[u8],
) -> Result<Option<WebSocketMessage>> {
    WebSocketCodec::client_default().decode_message(&mut wire(fin, opcode, payload, false))
}

pub(super) fn normal_close() -> WebSocketMessage {
    WebSocketMessage::Close(Some(WebSocketCloseFrame {
        code: WebSocketCloseCode::Normal,
        reason: String::from("finished"),
    }))
}
