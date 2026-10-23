//! RFC 6455 frame validation, masking, message assembly, and close lifecycle.

use crate::{Bytes, BytesMut, ProtoError, Result};

/// Endpoint role determines which direction requires masking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketRole {
    /// Sends masked frames and receives unmasked frames.
    Client,
    /// Sends unmasked frames and receives masked frames.
    Server,
}

/// Supported RFC 6455 frame opcodes; no extensions are negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WebSocketOpcode {
    /// Continues the current fragmented message.
    Continuation = 0x0,
    /// Starts a UTF-8 text message.
    Text = 0x1,
    /// Starts an opaque binary message.
    Binary = 0x2,
    /// Starts or acknowledges the close handshake.
    Close = 0x8,
    /// Requests a matching pong.
    Ping = 0x9,
    /// Carries a pong response or unsolicited heartbeat.
    Pong = 0xa,
}

impl WebSocketOpcode {
    fn parse(value: u8) -> Result<Self> {
        match value {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xa => Ok(Self::Pong),
            _ => Err(protocol("reserved opcode")),
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// Standard close statuses and application or registered extension statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum WebSocketCloseCode {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    /// Local observation only; never appears on the wire.
    NoStatusRcvd = 1005,
    /// Local observation only; never appears on the wire.
    Abnormal = 1006,
    InvalidFramePayloadData = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MandatoryExt = 1010,
    InternalError = 1011,
    Custom(u16),
}

impl WebSocketCloseCode {
    /// Converts a standard, registered, or application close status.
    ///
    /// Local statuses 1005 and 1006 are representable but cannot be transmitted.
    ///
    /// # Errors
    /// Returns a protocol error for an invalid or reserved close status.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn from_u16(code: u16) -> Result<Self> {
        match code {
            1000 => Ok(Self::Normal),
            1001 => Ok(Self::GoingAway),
            1002 => Ok(Self::ProtocolError),
            1003 => Ok(Self::UnsupportedData),
            1005 => Ok(Self::NoStatusRcvd),
            1006 => Ok(Self::Abnormal),
            1007 => Ok(Self::InvalidFramePayloadData),
            1008 => Ok(Self::PolicyViolation),
            1009 => Ok(Self::MessageTooBig),
            1010 => Ok(Self::MandatoryExt),
            1011 => Ok(Self::InternalError),
            1012..=1014 | 3000..=4999 => Ok(Self::Custom(code)),
            _ => Err(protocol("invalid or reserved close status")),
        }
    }

    /// Returns the numeric close status, including local observation statuses.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::GoingAway => 1001,
            Self::ProtocolError => 1002,
            Self::UnsupportedData => 1003,
            Self::NoStatusRcvd => 1005,
            Self::Abnormal => 1006,
            Self::InvalidFramePayloadData => 1007,
            Self::PolicyViolation => 1008,
            Self::MessageTooBig => 1009,
            Self::MandatoryExt => 1010,
            Self::InternalError => 1011,
            Self::Custom(code) => code,
        }
    }
}

/// A close status followed by a UTF-8 reason, together at most 125 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketCloseFrame {
    pub code: WebSocketCloseCode,
    pub reason: String,
}

/// One unmasked logical frame; masking is supplied by the encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketFrame {
    pub fin: bool,
    pub opcode: WebSocketOpcode,
    pub payload: Bytes,
}

/// Reassembled messages and independently delivered control frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebSocketMessage {
    Text(String),
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close(Option<WebSocketCloseFrame>),
}

/// Payload limits in bytes, excluding frame headers and masking keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketConfig {
    pub max_frame_size: usize,
    pub max_message_size: usize,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 1024 * 1024,
            max_message_size: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy)]
struct MessageState {
    opcode: WebSocketOpcode,
    size: usize,
    utf8_tail: [u8; 4],
    utf8_len: usize,
}

struct Fragment {
    state: MessageState,
    data: Vec<u8>,
}

/// Stateful, incremental Sans-IO WebSocket encoder and decoder.
///
/// Incoming protocol errors permanently stop decoding but permit one error
/// close to be sent. A received close can still be acknowledged once. Data
/// messages are forbidden after either side begins closing; control messages
/// never contribute to message-size limits.
pub struct WebSocketCodec {
    role: WebSocketRole,
    config: WebSocketConfig,
    incoming: Option<Fragment>,
    outgoing: Option<MessageState>,
    random: &'static dyn rustls::crypto::SecureRandom,
    close_sent: bool,
    close_received: bool,
    failed: bool,
}

impl WebSocketCodec {
    /// Creates an open codec with independent send and receive message state.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(role: WebSocketRole, config: WebSocketConfig) -> Self {
        Self {
            role,
            config,
            incoming: None,
            outgoing: None,
            random: rustls::crypto::ring::default_provider().secure_random,
            close_sent: false,
            close_received: false,
            failed: false,
        }
    }

    /// Creates a client codec with the default payload limits.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn client_default() -> Self {
        Self::new(WebSocketRole::Client, WebSocketConfig::default())
    }

    /// Creates a server codec with the default payload limits.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn server_default() -> Self {
        Self::new(WebSocketRole::Server, WebSocketConfig::default())
    }

    /// Encodes one complete message as one frame using the endpoint's masking.
    ///
    /// Larger messages can be explicitly fragmented using `encode_frame`.
    /// Errors leave both the output and send state unchanged.
    ///
    /// # Errors
    /// Returns a protocol, UTF-8, frame-size, message-size, or entropy error for
    /// invalid messages, exceeded limits, closing connections, or failed codecs.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn encode_message(&mut self, msg: &WebSocketMessage, out: &mut BytesMut) -> Result<()> {
        let (opcode, payload) = match msg {
            WebSocketMessage::Text(text) => {
                self.validate_send_state(WebSocketOpcode::Text)?;
                check_frame_size(text.len(), self.config.max_frame_size)?;
                check_message_size(0, text.len(), self.config.max_message_size)?;
                (
                    WebSocketOpcode::Text,
                    Bytes::copy_from_slice(text.as_bytes()),
                )
            }
            WebSocketMessage::Binary(data) => (WebSocketOpcode::Binary, data.clone()),
            WebSocketMessage::Ping(data) => (WebSocketOpcode::Ping, data.clone()),
            WebSocketMessage::Pong(data) => (WebSocketOpcode::Pong, data.clone()),
            WebSocketMessage::Close(None) => (WebSocketOpcode::Close, Bytes::new()),
            WebSocketMessage::Close(Some(close)) => {
                validate_close_code(close.code.as_u16())?;
                if close.reason.len() > 123 {
                    return Err(protocol("close reason exceeds 123 bytes"));
                }
                let mut data = Vec::with_capacity(2 + close.reason.len());
                data.extend_from_slice(&close.code.as_u16().to_be_bytes());
                data.extend_from_slice(close.reason.as_bytes());
                (WebSocketOpcode::Close, Bytes::from(data))
            }
        };
        self.encode_frame(
            &WebSocketFrame {
                fin: true,
                opcode,
                payload,
            },
            out,
        )
    }

    /// Encodes a frame, validating fragmentation, limits, and UTF-8 prefixes.
    ///
    /// Client masks come from the operating system's random source. A failed
    /// encode leaves the output and codec state unchanged, allowing correction.
    ///
    /// # Errors
    /// Returns a protocol, UTF-8, frame-size, message-size, or entropy error if
    /// the frame cannot legally be transmitted in the current connection state.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn encode_frame(&mut self, frame: &WebSocketFrame, out: &mut BytesMut) -> Result<()> {
        self.validate_send_state(frame.opcode)?;
        validate_frame(frame, self.config.max_frame_size)?;
        let next = if frame.opcode.is_control() {
            None
        } else {
            Some(next_message(
                self.outgoing,
                frame,
                self.config.max_message_size,
            )?)
        };
        let mut mask = [0u8; 4];
        let masked = self.role == WebSocketRole::Client;
        if masked {
            self.random
                .fill(&mut mask)
                .map_err(|_| protocol("mask entropy unavailable"))?;
        }
        let len = frame.payload.len();
        let mut wire = Vec::with_capacity(len.saturating_add(14));
        wire.push((if frame.fin { 0x80 } else { 0 }) | frame.opcode as u8);
        let mask_flag = if masked { 0x80 } else { 0 };
        if len < 126 {
            wire.push(mask_flag | len as u8);
        } else if len <= u16::MAX as usize {
            wire.push(mask_flag | 126);
            wire.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            let length = u64::try_from(len).map_err(|_| protocol("frame length overflow"))?;
            if length > i64::MAX as u64 {
                return Err(protocol("frame length exceeds 63 bits"));
            }
            wire.push(mask_flag | 127);
            wire.extend_from_slice(&length.to_be_bytes());
        }
        if masked {
            wire.extend_from_slice(&mask);
        }
        for (index, &byte) in frame.payload.iter().enumerate() {
            wire.push(if masked { byte ^ mask[index % 4] } else { byte });
        }
        out.extend_from_slice(&wire);
        if frame.opcode == WebSocketOpcode::Close {
            self.close_sent = true;
            self.outgoing = None;
        } else if !frame.opcode.is_control() {
            self.outgoing = if frame.fin { None } else { next };
        }
        Ok(())
    }

    /// Consumes complete frames until a message or control frame is available.
    ///
    /// Returns `None` for incomplete input, retaining any assembled fragments.
    /// Partial frames remain in `src`. Complete control frames are delivered
    /// immediately, including while a text or binary message is fragmented.
    /// Incoming validation errors fail the codec permanently.
    ///
    /// # Errors
    /// Returns named frame/message-limit errors or protocol/UTF-8 errors for
    /// malformed input, illegal state transitions, and use after failure.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn decode_message(&mut self, src: &mut BytesMut) -> Result<Option<WebSocketMessage>> {
        if self.failed {
            return Err(protocol("codec has failed"));
        }
        let result = self.decode_inner(src);
        if result.is_err() {
            self.failed = true;
            self.incoming = None;
            self.outgoing = None;
        }
        result
    }

    fn validate_send_state(&self, opcode: WebSocketOpcode) -> Result<()> {
        if self.failed && opcode != WebSocketOpcode::Close {
            return Err(protocol("codec has failed"));
        }
        if (self.close_sent && (opcode == WebSocketOpcode::Close || !opcode.is_control()))
            || (self.close_received && opcode != WebSocketOpcode::Close)
        {
            return Err(protocol("cannot send after closing"));
        }
        Ok(())
    }

    fn decode_inner(&mut self, src: &mut BytesMut) -> Result<Option<WebSocketMessage>> {
        loop {
            if src.is_empty() {
                return Ok(None);
            }
            if self.close_received {
                return Err(protocol("frame received after close"));
            }
            let Some((frame, consumed)) = self.read_frame(src.as_slice())? else {
                return Ok(None);
            };
            if self.close_sent && !frame.opcode.is_control() {
                return Err(protocol("data frame received after closing"));
            }
            let message = match frame.opcode {
                WebSocketOpcode::Ping => Some(WebSocketMessage::Ping(frame.payload)),
                WebSocketOpcode::Pong => Some(WebSocketMessage::Pong(frame.payload)),
                WebSocketOpcode::Close => {
                    let close = parse_close(frame.payload.as_slice())?;
                    self.close_received = true;
                    self.incoming = None;
                    self.outgoing = None;
                    Some(WebSocketMessage::Close(close))
                }
                _ => {
                    let prior = self.incoming.as_ref().map(|fragment| fragment.state);
                    let state = next_message(prior, &frame, self.config.max_message_size)?;
                    let mut next = match self.incoming.take() {
                        Some(fragment) => fragment,
                        None => Fragment {
                            state,
                            data: Vec::new(),
                        },
                    };
                    next.state = state;
                    next.data.extend_from_slice(frame.payload.as_slice());
                    if frame.fin {
                        Some(match next.state.opcode {
                            WebSocketOpcode::Text => WebSocketMessage::Text(
                                String::from_utf8(next.data)
                                    .map_err(|error| ProtoError::InvalidUtf8(error.to_string()))?,
                            ),
                            _ => WebSocketMessage::Binary(Bytes::from(next.data)),
                        })
                    } else {
                        self.incoming = Some(next);
                        None
                    }
                }
            };
            src.advance(consumed);
            if message.is_some() {
                return Ok(message);
            }
        }
    }

    fn read_frame(&self, src: &[u8]) -> Result<Option<(WebSocketFrame, usize)>> {
        if src.len() < 2 {
            return Ok(None);
        }
        if src[0] & 0x70 != 0 {
            return Err(protocol("reserved frame bits are set"));
        }
        let fin = src[0] & 0x80 != 0;
        let opcode = WebSocketOpcode::parse(src[0] & 0x0f)?;
        let masked = src[1] & 0x80 != 0;
        if masked != (self.role == WebSocketRole::Server) {
            return Err(protocol("incorrect masking for endpoint role"));
        }
        let short = src[1] & 0x7f;
        if opcode.is_control() && (!fin || short > 125) {
            return Err(protocol("fragmented or oversized control frame"));
        }
        let (len, mut header_len) = match short {
            126 => {
                if src.len() < 4 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([src[2], src[3]]) as usize;
                if len < 126 {
                    return Err(protocol("noncanonical 16-bit frame length"));
                }
                (len, 4usize)
            }
            127 => {
                if src.len() < 10 {
                    return Ok(None);
                }
                let len = u64::from_be_bytes([
                    src[2], src[3], src[4], src[5], src[6], src[7], src[8], src[9],
                ]);
                if len & (1 << 63) != 0 || len <= u16::MAX as u64 {
                    return Err(protocol("invalid or noncanonical 64-bit frame length"));
                }
                let len = usize::try_from(len).map_err(|_| ProtoError::WebSocketFrameTooLarge {
                    size: usize::MAX,
                    max: self.config.max_frame_size,
                })?;
                (len, 10usize)
            }
            _ => (short as usize, 2usize),
        };
        check_frame_size(len, self.config.max_frame_size)?;
        if !opcode.is_control() {
            let prior = self
                .incoming
                .as_ref()
                .map_or(0, |fragment| fragment.data.len());
            check_message_size(prior, len, self.config.max_message_size)?;
        }
        let mut mask = [0; 4];
        if masked {
            if src.len() < header_len + 4 {
                return Ok(None);
            }
            mask.copy_from_slice(&src[header_len..header_len + 4]);
            header_len += 4;
        }
        let consumed = header_len
            .checked_add(len)
            .ok_or_else(|| protocol("frame length overflow"))?;
        if src.len() < consumed {
            return Ok(None);
        }
        let mut payload = src[header_len..consumed].to_vec();
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        let frame = WebSocketFrame {
            fin,
            opcode,
            payload: Bytes::from(payload),
        };
        validate_frame(&frame, self.config.max_frame_size)?;
        Ok(Some((frame, consumed)))
    }
}

fn protocol(reason: &str) -> ProtoError {
    ProtoError::WebSocketProtocol(reason.to_owned())
}

fn check_frame_size(size: usize, max: usize) -> Result<()> {
    if size > max {
        Err(ProtoError::WebSocketFrameTooLarge { size, max })
    } else {
        Ok(())
    }
}

fn check_message_size(prior: usize, extra: usize, max: usize) -> Result<usize> {
    let size = prior
        .checked_add(extra)
        .ok_or(ProtoError::WebSocketMessageTooLarge {
            size: usize::MAX,
            max,
        })?;
    if size > max {
        Err(ProtoError::WebSocketMessageTooLarge { size, max })
    } else {
        Ok(size)
    }
}

fn validate_close_code(code: u16) -> Result<WebSocketCloseCode> {
    let code = WebSocketCloseCode::from_u16(code)?;
    if matches!(
        code,
        WebSocketCloseCode::NoStatusRcvd | WebSocketCloseCode::Abnormal
    ) {
        Err(protocol("local close status is forbidden on the wire"))
    } else {
        Ok(code)
    }
}

fn parse_close(payload: &[u8]) -> Result<Option<WebSocketCloseFrame>> {
    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() == 1 {
        return Err(protocol("close payload contains a partial status"));
    }
    let code = validate_close_code(u16::from_be_bytes([payload[0], payload[1]]))?;
    let reason = std::str::from_utf8(&payload[2..])
        .map_err(|error| ProtoError::InvalidUtf8(error.to_string()))?;
    Ok(Some(WebSocketCloseFrame {
        code,
        reason: reason.to_owned(),
    }))
}

fn validate_frame(frame: &WebSocketFrame, max: usize) -> Result<()> {
    check_frame_size(frame.payload.len(), max)?;
    if frame.opcode.is_control() {
        if !frame.fin || frame.payload.len() > 125 {
            return Err(protocol("fragmented or oversized control frame"));
        }
        if frame.opcode == WebSocketOpcode::Close {
            parse_close(frame.payload.as_slice())?;
        }
    }
    Ok(())
}

fn next_message(
    prior: Option<MessageState>,
    frame: &WebSocketFrame,
    max: usize,
) -> Result<MessageState> {
    let opcode = match (prior, frame.opcode) {
        (Some(state), WebSocketOpcode::Continuation) => state.opcode,
        (None, WebSocketOpcode::Text | WebSocketOpcode::Binary) => frame.opcode,
        (None, WebSocketOpcode::Continuation) => {
            return Err(protocol("unexpected continuation frame"));
        }
        _ => return Err(protocol("new data frame during fragmented message")),
    };
    let prior_len = prior.map_or(0, |state| state.size);
    let size = check_message_size(prior_len, frame.payload.len(), max)?;
    let (utf8_tail, utf8_len) = if opcode == WebSocketOpcode::Text {
        let (tail, len) = prior.map_or(([0; 4], 0), |state| (state.utf8_tail, state.utf8_len));
        validate_utf8(&tail[..len], frame.payload.as_slice(), frame.fin)?
    } else {
        ([0; 4], 0)
    };
    Ok(MessageState {
        opcode,
        size,
        utf8_tail,
        utf8_len,
    })
}

fn validate_utf8(previous: &[u8], mut data: &[u8], fin: bool) -> Result<([u8; 4], usize)> {
    let mut tail = [0; 4];
    if let Some(&lead) = previous.first() {
        let width = match lead {
            0xc2..=0xdf => 2usize,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(protocol("invalid UTF-8 continuation state")),
        };
        let required = width - previous.len();
        let take = required.min(data.len());
        let len = previous.len() + take;
        tail[..previous.len()].copy_from_slice(previous);
        tail[previous.len()..len].copy_from_slice(&data[..take]);
        if let Err(error) = std::str::from_utf8(&tail[..len]) {
            if fin || error.error_len().is_some() {
                return Err(ProtoError::InvalidUtf8(error.to_string()));
            }
            return Ok((tail, len));
        }
        data = &data[take..];
    }
    match std::str::from_utf8(data) {
        Ok(_) => Ok(([0; 4], 0)),
        Err(error) if !fin && error.error_len().is_none() => {
            let suffix = &data[error.valid_up_to()..];
            tail[..suffix.len()].copy_from_slice(suffix);
            Ok((tail, suffix.len()))
        }
        Err(error) => Err(ProtoError::InvalidUtf8(error.to_string())),
    }
}
