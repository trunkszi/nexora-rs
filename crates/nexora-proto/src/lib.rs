//! Sans-IO byte buffers, protocol models, and incremental wire codecs.

pub mod bytes;
pub mod error;
pub mod headers;
pub mod http1;
pub mod http2;
pub mod tls;
pub mod uri;
pub mod websocket;

pub use bytes::{Bytes, BytesMut};
pub use error::{Http2ErrorCode, ProtoError, Result};
pub use headers::{HeaderField, HeaderMapExt, Headers};
pub use http1::{
    Http1ClientCodec, Http1ClientConfig, Http1Event, Http1KeepAlive, Http1ServerCodec,
    Http1ServerConfig, Method, Request, Response, StatusCode, Version,
};
pub use http2::{
    HpackDecoder, HpackEncoder, Http2Config, Http2Connection, Http2Event, Http2Frame,
    Http2FrameHeader, Http2FrameType, Http2Role, Http2Settings,
};
pub use tls::{AlpnProtocol, TlsClientConfig, TlsRole, TlsServerConfig, TlsSession};
pub use uri::{Scheme, Uri};
pub use websocket::{
    WebSocketCloseCode, WebSocketCloseFrame, WebSocketCodec, WebSocketConfig, WebSocketFrame,
    WebSocketHandshake, WebSocketMessage, WebSocketOpcode, WebSocketRole,
};
