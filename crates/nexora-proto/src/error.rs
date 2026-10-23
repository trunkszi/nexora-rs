//! Protocol failures independent of transport or operating system state.

/// HTTP/2 error codes defined by RFC 9113.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Http2ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

impl Http2ErrorCode {
    /// Interpret a wire code, treating unknown codes as an internal error.
    pub const fn from_u32(code: u32) -> Self {
        match code {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            _ => Self::InternalError,
        }
    }

    /// Return the wire representation.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// A protocol operation's result.
pub type Result<T> = std::result::Result<T, ProtoError>;

/// Parsing, framing, resource-limit, and TLS failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    #[error("incomplete frame or message")]
    Incomplete,
    #[error("invalid HTTP method: {0}")]
    InvalidMethod(String),
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    #[error("invalid HTTP version: {0}")]
    InvalidVersion(String),
    #[error("invalid status code: {0}")]
    InvalidStatusCode(u16),
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    #[error("missing required header: {0}")]
    MissingHeader(String),
    #[error("header list size {size} exceeds maximum {max}")]
    HeaderListTooLarge { size: usize, max: usize },
    #[error("body size {size} exceeds maximum {max}")]
    BodyTooLarge { size: usize, max: usize },
    #[error("invalid chunked encoding: {0}")]
    InvalidChunkedEncoding(String),
    #[error("HTTP/1.1 protocol error: {0}")]
    Http1Protocol(String),
    #[error("HTTP/2 connection error ({code:?}): {reason}")]
    Http2ConnectionError {
        code: Http2ErrorCode,
        reason: String,
    },
    #[error("HTTP/2 stream {stream_id} error ({code:?}): {reason}")]
    Http2StreamError {
        stream_id: u32,
        code: Http2ErrorCode,
        reason: String,
    },
    #[error("HPACK compression error: {0}")]
    Hpack(String),
    #[error("WebSocket protocol error: {0}")]
    WebSocketProtocol(String),
    #[error("WebSocket frame size {size} exceeds maximum {max}")]
    WebSocketFrameTooLarge { size: usize, max: usize },
    #[error("WebSocket message size {size} exceeds maximum {max}")]
    WebSocketMessageTooLarge { size: usize, max: usize },
    #[error("invalid UTF-8 in text payload: {0}")]
    InvalidUtf8(String),
    #[error("TLS error: {0}")]
    Tls(String),
}
