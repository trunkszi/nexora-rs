//! RFC 6455 upgrade handshakes and role-aware message framing.

mod frame;
mod handshake;

pub use frame::{
    WebSocketCloseCode, WebSocketCloseFrame, WebSocketCodec, WebSocketConfig, WebSocketFrame,
    WebSocketMessage, WebSocketOpcode, WebSocketRole,
};
pub use handshake::WebSocketHandshake;
