//! Sans-IO HTTP/2 connection and multiplexed stream lifecycle.
use std::collections::{BTreeMap, VecDeque};

use super::{
    HpackDecoder, HpackEncoder, Http2Frame, Http2Settings, connection_error, explicit_push_enabled,
    frame::{self, CLIENT_PREFACE, DEFAULT_INITIAL_WINDOW_SIZE, MAX_FLOW_CONTROL_WINDOW},
    stream_error, validate_headers, validate_settings,
};
use crate::{
    Bytes, BytesMut, Headers, Http2ErrorCode, Method, ProtoError, Request, Response, Result,
    StatusCode, Uri, Version,
};

/// Endpoint role; server push is intentionally disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http2Role {
    Client,
    Server,
}
/// Local receive limits and advertised connection settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Config {
    pub local_settings: Http2Settings,
    pub max_body_size: usize,
}
#[rustfmt::skip]
impl Default for Http2Config {
    fn default() -> Self {
        Self { local_settings: Http2Settings { enable_push: false, ..Http2Settings::default() }, max_body_size: 16 * 1024 * 1024 }
    }
}
/// Completed messages and connection or stream lifecycle notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
#[rustfmt::skip]
pub enum Http2Event {
    RequestReceived { stream_id: u32, request: Request },
    ResponseReceived { stream_id: u32, response: Response },
    StreamReset { stream_id: u32, error_code: Http2ErrorCode },
    StreamBodyTooLarge { stream_id: u32, size: usize, max: usize },
    SettingsAcknowledged,
    PingAcknowledged([u8; 8]),
    GoAwayReceived { last_stream_id: u32, error_code: Http2ErrorCode, debug_data: Bytes },
}
struct Stream {
    send_window: i64,
    recv_window: i64,
    outgoing: Bytes,
    offset: usize,
    local_closed: bool,
    remote_closed: bool,
    send_started: bool,
    headers: Option<Vec<(String, String)>>,
    body: BytesMut,
    head_request: bool,
}
#[rustfmt::skip]
impl Stream {
    fn new(send: i64, recv: i64) -> Self {
        Self { send_window: send, recv_window: recv, outgoing: Bytes::new(), offset: 0,
            local_closed: false, remote_closed: false, send_started: false,
            headers: None, body: BytesMut::new(), head_request: false }
    }
}
struct HeaderBlock {
    stream_id: u32,
    end_stream: bool,
    bytes: BytesMut,
    discard: bool,
}
/// A transport-independent, single-threaded HTTP/2 multiplexer.
pub struct Http2Connection {
    role: Http2Role,
    config: Http2Config,
    peer: Http2Settings,
    streams: BTreeMap<u32, Stream>,
    seen_peer_streams: BTreeMap<u32, u32>,
    events: VecDeque<Http2Event>,
    tx: BytesMut,
    encoder: HpackEncoder,
    decoder: HpackDecoder,
    preface: usize,
    received_settings: bool,
    awaiting_ack: bool,
    next_stream: u32,
    last_peer_stream: u32,
    processed_peer_stream: u32,
    send_window: i64,
    recv_window: i64,
    block: Option<HeaderBlock>,
    sent_goaway: Option<u32>,
    received_goaway: Option<u32>,
    failure: Option<ProtoError>,
}
#[rustfmt::skip]
impl Http2Connection {
    /// Creates a connection and queues its initial SETTINGS and client preface.
    /// # Errors
    /// This constructor does not return errors; invalid settings fail on protocol operations.
    /// # Panics
    /// Does not panic.
    pub fn new(role: Http2Role, mut config: Http2Config) -> Self {
        config.local_settings.enable_push = false;
        let mut tx = BytesMut::new();
        if role == Http2Role::Client {
            tx.extend_from_slice(CLIENT_PREFACE);
        }
        let failure =
            validate_settings(config.local_settings).and_then(|()| frame::encode_frame(&Http2Frame::Settings { ack: false, settings: config.local_settings }, &mut tx)).err();
        Self {
            role,
            config,
            peer: Http2Settings::default(),
            streams: BTreeMap::new(),
            seen_peer_streams: BTreeMap::new(),
            events: VecDeque::new(),
            tx,
            encoder: HpackEncoder::new(4096),
            decoder: HpackDecoder::new(config.local_settings.header_table_size.max(4096) as usize, config.local_settings.max_header_list_size as usize),
            preface: if role == Http2Role::Client { 24 } else { 0 },
            received_settings: false,
            awaiting_ack: true,
            next_stream: 1,
            last_peer_stream: 0,
            processed_peer_stream: 0,
            send_window: DEFAULT_INITIAL_WINDOW_SIZE,
            recv_window: DEFAULT_INITIAL_WINDOW_SIZE,
            block: None,
            sent_goaway: None,
            received_goaway: None,
            failure,
        }
    }
    /// Creates a client with default limits.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn client_default() -> Self { Self::new(Http2Role::Client, Http2Config::default()) }
    /// Creates a server with default limits.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn server_default() -> Self { Self::new(Http2Role::Server, Http2Config::default()) }
    /// Returns the local endpoint role.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn role(&self) -> Http2Role { self.role }
    /// Consumes complete frames, retaining incomplete frames in `src`.
    /// # Errors
    /// Returns protocol, compression, stream, or flow-control errors for invalid input.
    /// # Panics
    /// Does not panic.
    pub fn feed_bytes(&mut self, src: &mut BytesMut) -> Result<()> {
        self.check_live()?;
        let result = self.feed_inner(src);
        if let Err(error) = &result {
            match error {
                ProtoError::Http2ConnectionError { code, .. } => {
                    let _queued = self.queue(Http2Frame::GoAway { last_stream_id: self.last_peer_stream, error_code: *code, debug_data: Bytes::new() });
                    self.failure = Some(error.clone());
                }
                ProtoError::Http2StreamError { stream_id, code, .. } => {
                    self.streams.remove(stream_id);
                    let _queued = self.queue(Http2Frame::RstStream { stream_id: *stream_id, error_code: *code });
                }
                _ => {}
            }
        }
        result
    }
    /// Removes the next completed-message or lifecycle notification.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn poll_event(&mut self) -> Option<Http2Event> {
        self.events.pop_front()
    }
    /// Appends all currently queued wire bytes to `out`.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn take_tx_bytes(&mut self, out: &mut BytesMut) {
        out.extend_from_slice(self.tx.as_slice());
        self.tx.clear();
    }
    /// Reports whether encoded wire bytes are available.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn has_tx_bytes(&self) -> bool {
        !self.tx.is_empty()
    }
    /// Opens an odd-numbered client stream and queues a request.
    /// # Errors
    /// Returns an error for the wrong role, draining connections, exhausted limits, or invalid headers.
    /// # Panics
    /// Does not panic.
    pub fn submit_request(&mut self, req: &Request) -> Result<u32> {
        self.check_live()?;
        if !self.can_open_stream() {
            return Err(connection_error(Http2ErrorCode::RefusedStream, "cannot open request stream"));
        }
        let id = self.next_stream;
        let mut fields = vec![(":method".into(), req.method.as_str().into())];
        if req.method != Method::Connect {
            fields.push((":scheme".into(), req.uri.scheme().as_str().into()));
            fields.push((":path".into(), req.uri.path_and_query().into()));
        }
        fields.push((":authority".into(), req.uri.authority()));
        fields.extend(req.headers.iter().filter(|field| field.name != "host").map(|field| (field.name.clone(), field.value.clone())));
        validate_headers(&fields, Http2Role::Server, false, id)?;
        if req.headers.content_length()?.is_some_and(|size| size != req.body.len()) {
            return Err(stream_error(id, Http2ErrorCode::ProtocolError, "request content length disagrees with body"));
        }
        if req.headers.get("host").is_some_and(|host| !host.eq_ignore_ascii_case(&req.uri.authority())) {
            return Err(stream_error(id, Http2ErrorCode::ProtocolError, "host disagrees with request authority"));
        }
        self.encode_headers(id, &fields, req.body.is_empty())?;
        let mut stream = self.new_stream();
        stream.outgoing = req.body.clone();
        stream.send_started = true;
        stream.local_closed = req.body.is_empty();
        stream.head_request = req.method == Method::Head;
        self.streams.insert(id, stream);
        self.next_stream += 2;
        self.flush_data()?;
        Ok(id)
    }
    /// Queues a final response on an existing server stream.
    /// # Errors
    /// Returns an error for closed streams, invalid roles, or invalid response headers.
    /// # Panics
    /// Does not panic.
    pub fn submit_response(&mut self, stream_id: u32, resp: &Response) -> Result<()> {
        self.check_live()?;
        let stream = self.streams.get(&stream_id).ok_or_else(|| stream_error(stream_id, Http2ErrorCode::StreamClosed, "unknown response stream"))?;
        if self.role != Http2Role::Server || stream.send_started || !stream.remote_closed {
            return Err(stream_error(stream_id, Http2ErrorCode::ProtocolError, "response stream is not ready"));
        }
        let mut fields = vec![(":status".into(), resp.status.as_u16().to_string())];
        fields.extend(resp.headers.iter().map(|field| (field.name.clone(), field.value.clone())));
        validate_headers(&fields, Http2Role::Client, false, stream_id)?;
        if resp.status.is_informational() {
            return Err(stream_error(stream_id, Http2ErrorCode::ProtocolError, "final response required"));
        }
        let no_body = stream.head_request || matches!(resp.status.as_u16(), 204 | 304);
        let length = resp.headers.content_length()?;
        if (resp.status.as_u16() == 204 && length.is_some()) || (!no_body && length.is_some_and(|size| size != resp.body.len())) {
            return Err(stream_error(stream_id, Http2ErrorCode::ProtocolError, "response content length disagrees with semantics"));
        }
        let body = if no_body { Bytes::new() } else { resp.body.clone() };
        self.encode_headers(stream_id, &fields, body.is_empty())?;
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.local_closed = body.is_empty();
            stream.outgoing = body;
            stream.send_started = true;
        }
        self.flush_data()?;
        self.retire();
        Ok(())
    }
    /// Cancels one stream without closing sibling streams.
    /// # Errors
    /// Returns an error if the connection failed or the stream is not active.
    /// # Panics
    /// Does not panic.
    pub fn cancel_stream(&mut self, stream_id: u32) -> Result<()> {
        self.check_live()?;
        if self.streams.remove(&stream_id).is_none() {
            return Err(stream_error(stream_id, Http2ErrorCode::StreamClosed, "cannot cancel inactive stream"));
        }
        self.queue(Http2Frame::RstStream { stream_id, error_code: Http2ErrorCode::Cancel })
    }
    /// Queues a connection liveness probe.
    /// # Errors
    /// Returns an error if the connection failed.
    /// # Panics
    /// Does not panic.
    pub fn send_ping(&mut self, opaque_data: [u8; 8]) -> Result<()> {
        self.check_live()?;
        self.queue(Http2Frame::Ping { ack: false, opaque_data })
    }
    /// Stops accepting new streams while existing accepted streams drain.
    /// # Errors
    /// Returns an error for an invalid cutoff or debug data exceeding the peer frame limit.
    /// # Panics
    /// Does not panic.
    pub fn send_goaway(&mut self, last_stream_id: u32, code: Http2ErrorCode, debug_data: Bytes) -> Result<()> {
        self.check_live()?;
        if last_stream_id > 0x7fff_ffff || last_stream_id < self.processed_peer_stream || self.sent_goaway.is_some_and(|old| last_stream_id > old) {
            return Err(connection_error(Http2ErrorCode::ProtocolError, "invalid GOAWAY stream identifier"));
        }
        if debug_data.len().saturating_add(8) > self.peer.max_frame_size as usize {
            return Err(connection_error(Http2ErrorCode::FrameSizeError, "GOAWAY exceeds peer frame size"));
        }
        self.queue(Http2Frame::GoAway { last_stream_id, error_code: code, debug_data })?;
        self.sent_goaway = Some(last_stream_id);
        Ok(())
    }
    /// Counts streams that have not closed both directions.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn active_stream_count(&self) -> usize { self.streams.len() }
    /// Reports whether a new client request can be submitted.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn can_open_stream(&self) -> bool {
        self.role == Http2Role::Client
            && self.failure.is_none()
            && self.sent_goaway.is_none()
            && self.received_goaway.is_none()
            && self.next_stream <= 0x7fff_ffff
            && self.streams.len() < self.peer.max_concurrent_streams as usize
    }
    /// Returns remaining connection-level send credit.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn connection_send_window(&self) -> i64 { self.send_window }
    /// Returns signed send credit for an active stream.
    /// # Errors
    /// This operation is infallible.
    /// # Panics
    /// Does not panic.
    pub fn stream_send_window(&self, stream_id: u32) -> Option<i64> { self.streams.get(&stream_id).map(|s| s.send_window) }
    fn check_live(&self) -> Result<()> {
        match &self.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
    fn queue(&mut self, frame: Http2Frame) -> Result<()> { frame::encode_frame(&frame, &mut self.tx) }
    fn new_stream(&self) -> Stream {
        Stream::new(i64::from(self.peer.initial_window_size), i64::from(self.config.local_settings.initial_window_size))
    }
    fn retire(&mut self) { self.streams.retain(|_, stream| !(stream.local_closed && stream.remote_closed)); }
    fn feed_inner(&mut self, src: &mut BytesMut) -> Result<()> {
        while self.preface < CLIENT_PREFACE.len() && !src.is_empty() {
            if src[0] != CLIENT_PREFACE[self.preface] {
                return Err(connection_error(Http2ErrorCode::ProtocolError, "invalid client connection preface"));
            }
            src.advance(1);
            self.preface += 1;
        }
        if self.preface < CLIENT_PREFACE.len() {
            return Ok(());
        }
        loop {
            if src.len() >= 9 {
                let id = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) & 0x7fff_ffff;
                if !self.received_settings && (src[3] != 4 || src[4] & 1 != 0) {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "first peer frame must be SETTINGS"));
                }
                if self.block.as_ref().is_some_and(|block| src[3] != 9 || id != block.stream_id) {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "interleaved header block"));
                }
            }
            let merged = merged_settings(src.as_slice(), self.peer, &self.streams)?;
            if self.role == Http2Role::Client && explicit_push_enabled(src.as_slice()) {
                return Err(connection_error(Http2ErrorCode::ProtocolError, "server enabled unsupported push"));
            }
            let flow_len = if src.len() >= 9 { (usize::from(src[0]) << 16) | (usize::from(src[1]) << 8) | usize::from(src[2]) } else { 0 };
            let decoded = frame::decode_frame(src, self.config.local_settings.max_frame_size);
            if matches!(decoded, Err(ProtoError::Http2StreamError { .. })) {
                if src.len() < 9 + flow_len { break; }
                if src[3] == 1 {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "invalid prioritized header block"));
                }
                if src[3] != 2 && self.is_idle(u32::from_be_bytes([src[5], src[6], src[7], src[8]]) & 0x7fff_ffff) {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "invalid frame on idle stream"));
                }
                src.advance(9 + flow_len);
            }
            let Some(mut frame) = decoded? else {
                break;
            };
            if let (Some((settings, table_sizes)), Http2Frame::Settings { ack: false, .. }) = (merged, &frame) {
                for size in table_sizes { self.encoder.set_max_table_size(size); }
                frame = Http2Frame::Settings { ack: false, settings };
            }
            self.handle_frame(frame, flow_len)?;
        }
        Ok(())
    }
    fn handle_frame(&mut self, frame: Http2Frame, flow_len: usize) -> Result<()> {
        match frame {
            Http2Frame::Settings { ack: true, .. } => {
                if !self.awaiting_ack {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "unexpected SETTINGS acknowledgement"));
                }
                self.awaiting_ack = false;
                self.decoder.set_max_table_size(self.config.local_settings.header_table_size as usize);
                self.events.push_back(Http2Event::SettingsAcknowledged);
            }
            Http2Frame::Settings { ack: false, settings } => {
                validate_settings(settings)?;
                let delta = i64::from(settings.initial_window_size) - i64::from(self.peer.initial_window_size);
                if self.streams.values().any(|stream| stream.send_window + delta > MAX_FLOW_CONTROL_WINDOW) {
                    return Err(connection_error(Http2ErrorCode::FlowControlError, "SETTINGS increases stream window beyond limit"));
                }
                for stream in self.streams.values_mut() {
                    stream.send_window += delta;
                }
                self.encoder.set_max_table_size(settings.header_table_size as usize);
                self.peer = settings;
                self.received_settings = true;
                self.queue(Http2Frame::Settings { ack: true, settings: self.config.local_settings })?;
                self.flush_data()?;
            }
            Http2Frame::Headers { stream_id, end_stream, end_headers, header_block } => {
                let discard = !self.accept_headers(stream_id)?;
                let mut bytes = BytesMut::new();
                bytes.extend_from_slice(header_block.as_slice());
                self.block = Some(HeaderBlock { stream_id, end_stream, bytes, discard });
                if end_headers {
                    self.finish_headers()?;
                }
            }
            Http2Frame::Continuation { stream_id, end_headers, header_block } => {
                let block = self.block.as_mut().ok_or_else(|| connection_error(Http2ErrorCode::ProtocolError, "unexpected CONTINUATION"))?;
                if block.stream_id != stream_id {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "wrong CONTINUATION stream"));
                }
                block.bytes.extend_from_slice(header_block.as_slice());
                if block.bytes.len() > (self.config.local_settings.max_header_list_size as usize).saturating_mul(2).saturating_add(1024) {
                    return Err(connection_error(Http2ErrorCode::EnhanceYourCalm, "compressed header block too large"));
                }
                if end_headers {
                    self.finish_headers()?;
                }
            }
            Http2Frame::Data { stream_id, end_stream, data } => self.receive_data(stream_id, end_stream, data, flow_len)?,
            Http2Frame::WindowUpdate { stream_id, increment } => self.window_update(stream_id, increment)?,
            Http2Frame::RstStream { stream_id, error_code } => {
                if self.is_idle(stream_id) {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "RST_STREAM on idle stream"));
                }
                if self.streams.remove(&stream_id).is_some() {
                    self.events.push_back(Http2Event::StreamReset { stream_id, error_code });
                }
            }
            Http2Frame::Ping { ack, opaque_data } => {
                if ack {
                    self.events.push_back(Http2Event::PingAcknowledged(opaque_data));
                } else {
                    self.queue(Http2Frame::Ping { ack: true, opaque_data })?;
                }
            }
            Http2Frame::GoAway { last_stream_id, error_code, debug_data } => {
                if self.received_goaway.is_some_and(|old| last_stream_id > old) {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "GOAWAY increases last stream identifier"));
                }
                self.received_goaway = Some(last_stream_id);
                if self.role == Http2Role::Client {
                    let refused: Vec<_> = self.streams.range((last_stream_id.saturating_add(1))..).map(|(&id, _)| id).collect();
                    for stream_id in refused {
                        self.streams.remove(&stream_id);
                        self.events.push_back(Http2Event::StreamReset { stream_id, error_code: Http2ErrorCode::RefusedStream });
                    }
                }
                self.events.push_back(Http2Event::GoAwayReceived { last_stream_id, error_code, debug_data });
            }
            Http2Frame::Priority { .. } => {}
            Http2Frame::Unknown { header, .. } => {
                if matches!(header.frame_type, super::Http2FrameType::PushPromise) {
                    return Err(connection_error(Http2ErrorCode::ProtocolError, "server push is disabled"));
                }
            }
        }
        self.retire();
        Ok(())
    }
    fn was_peer_stream(&self, id: u32) -> bool {
        self.seen_peer_streams.range(..=id).next_back().is_some_and(|(_, &end)| id <= end)
    }
    fn record_peer_stream(&mut self, id: u32) {
        match self.seen_peer_streams.last_entry() {
            Some(mut entry) if entry.get().saturating_add(2) == id => { *entry.get_mut() = id; }
            _ => { self.seen_peer_streams.insert(id, id); }
        }
    }
    fn is_idle(&self, id: u32) -> bool {
        id == 0 || id.is_multiple_of(2) || if self.role == Http2Role::Client { id >= self.next_stream } else { id > self.last_peer_stream }
    }
    fn accept_headers(&mut self, id: u32) -> Result<bool> {
        if let Some(stream) = self.streams.get(&id) {
            if stream.remote_closed {
                self.streams.remove(&id);
                self.queue(Http2Frame::RstStream { stream_id: id, error_code: Http2ErrorCode::StreamClosed })?;
                return Ok(false);
            }
            return Ok(true);
        }
        if id == 0 || id.is_multiple_of(2) || self.is_idle(id) && self.role == Http2Role::Client {
            return Err(connection_error(Http2ErrorCode::ProtocolError, "invalid new stream identifier"));
        }
        if !self.is_idle(id) {
            if self.role == Http2Role::Server && !self.was_peer_stream(id) {
                return Err(connection_error(Http2ErrorCode::ProtocolError, "new stream identifier is not increasing"));
            }
            return Ok(false);
        }
        self.last_peer_stream = id;
        self.record_peer_stream(id);
        if self.sent_goaway.is_some_and(|last| id > last) || self.streams.len() >= self.config.local_settings.max_concurrent_streams as usize {
            self.queue(Http2Frame::RstStream { stream_id: id, error_code: Http2ErrorCode::RefusedStream })?;
            return Ok(false);
        }
        self.streams.insert(id, self.new_stream());
        Ok(true)
    }
    fn finish_headers(&mut self) -> Result<()> {
        let block = self.block.take().ok_or_else(|| connection_error(Http2ErrorCode::ProtocolError, "missing header block"))?;
        let fields = match self.decoder.decode(block.bytes.as_slice()) {
            Ok(fields) => fields,
            Err(ProtoError::HeaderListTooLarge { .. }) if block.discard => return Ok(()),
            Err(ProtoError::HeaderListTooLarge { .. }) => return Err(stream_error(block.stream_id, Http2ErrorCode::EnhanceYourCalm, "header list too large")),
            Err(error) => return Err(connection_error(Http2ErrorCode::CompressionError, &error.to_string())),
        };
        if block.discard {
            return Ok(());
        }
        let stream = self.streams.get_mut(&block.stream_id).ok_or_else(|| stream_error(block.stream_id, Http2ErrorCode::StreamClosed, "headers on closed stream"))?;
        let trailers = stream.headers.is_some();
        validate_headers(&fields, self.role, trailers, block.stream_id)?;
        if trailers && !block.end_stream {
            return Err(stream_error(block.stream_id, Http2ErrorCode::ProtocolError, "trailers must end stream"));
        }
        if !trailers && self.role == Http2Role::Client && fields.iter().any(|(name, value)| name == ":status" && value.starts_with('1')) {
            if block.end_stream {
                return Err(stream_error(block.stream_id, Http2ErrorCode::ProtocolError, "informational response ends stream"));
            }
            return Ok(());
        }
        if let Some(headers) = &mut stream.headers {
            headers.extend(fields);
        } else {
            stream.headers = Some(fields);
        }
        if block.end_stream {
            self.complete_message(block.stream_id)?;
        }
        Ok(())
    }
    fn receive_data(&mut self, id: u32, end: bool, data: Bytes, flow_len: usize) -> Result<()> {
        let credit = flow_len as i64;
        if credit > self.recv_window {
            return Err(connection_error(Http2ErrorCode::FlowControlError, "connection receive window exhausted"));
        }
        self.recv_window -= credit;
        if credit != 0 {
            self.queue(Http2Frame::WindowUpdate { stream_id: 0, increment: flow_len as u32 })?;
            self.recv_window += credit;
        }
        let Some(stream) = self.streams.get_mut(&id) else {
            if self.is_idle(id) {
                return Err(connection_error(Http2ErrorCode::ProtocolError, "DATA on idle stream"));
            }
            return Ok(());
        };
        if stream.remote_closed || stream.headers.is_none() {
            return Err(stream_error(id, Http2ErrorCode::StreamClosed, "DATA outside open message"));
        }
        if credit > stream.recv_window {
            return Err(stream_error(id, Http2ErrorCode::FlowControlError, "stream receive window exhausted"));
        }
        stream.recv_window -= credit;
        let size = stream.body.len().saturating_add(data.len());
        if size > self.config.max_body_size {
            self.events.push_back(Http2Event::StreamBodyTooLarge { stream_id: id, size, max: self.config.max_body_size });
            self.streams.remove(&id);
            return self.queue(Http2Frame::RstStream { stream_id: id, error_code: Http2ErrorCode::Cancel });
        }
        stream.body.extend_from_slice(data.as_slice());
        stream.recv_window += credit;
        if credit != 0 {
            self.queue(Http2Frame::WindowUpdate { stream_id: id, increment: flow_len as u32 })?;
        }
        if end {
            self.complete_message(id)?;
        }
        Ok(())
    }
    fn complete_message(&mut self, id: u32) -> Result<()> {
        let stream = self.streams.get_mut(&id).ok_or_else(|| stream_error(id, Http2ErrorCode::StreamClosed, "message stream closed"))?;
        let fields = stream.headers.as_ref().ok_or_else(|| stream_error(id, Http2ErrorCode::ProtocolError, "message has no headers"))?;
        let mut headers = Headers::new();
        for (name, value) in fields {
            if !name.starts_with(':') {
                headers.append(name.clone(), value.clone());
            }
        }
        let pseudo = |key: &str| fields.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str());
        let length = headers.content_length().map_err(|_| stream_error(id, Http2ErrorCode::ProtocolError, "invalid content length"))?;
        let no_body = self.role == Http2Role::Client && (stream.head_request || matches!(pseudo(":status"), Some("204" | "304")));
        if self.role == Http2Role::Client && pseudo(":status") == Some("204") && length.is_some() {
            return Err(stream_error(id, Http2ErrorCode::ProtocolError, "204 response includes content length"));
        }
        if (!no_body && length.is_some_and(|length| length != stream.body.len())) || (no_body && !stream.body.is_empty()) {
            return Err(stream_error(id, Http2ErrorCode::ProtocolError, "message body disagrees with content length or semantics"));
        }
        let body = Bytes::new();
        let mut event = if self.role == Http2Role::Server {
            let method = Method::parse(pseudo(":method").unwrap_or_default()).map_err(|_| stream_error(id, Http2ErrorCode::ProtocolError, "invalid request method"))?;
            let authority = pseudo(":authority").or_else(|| headers.get("host")).unwrap_or_default();
            let scheme = pseudo(":scheme").unwrap_or("http");
            let path = pseudo(":path").unwrap_or("/");
            let uri = Uri::parse(&format!("{scheme}://{authority}{path}")).map_err(|_| stream_error(id, Http2ErrorCode::ProtocolError, "invalid request URI"))?;
            stream.head_request = method == Method::Head;
            self.processed_peer_stream = self.processed_peer_stream.max(id);
            Http2Event::RequestReceived { stream_id: id, request: Request { method, uri, version: Version::Http2, headers, body } }
        } else {
            let status = pseudo(":status").and_then(|value| value.parse::<u16>().ok()).ok_or_else(|| stream_error(id, Http2ErrorCode::ProtocolError, "missing response status"))?;
            Http2Event::ResponseReceived {
                stream_id: id,
                response: Response {
                    status: StatusCode::new(status).map_err(|_| stream_error(id, Http2ErrorCode::ProtocolError, "invalid response status"))?,
                    version: Version::Http2,
                    headers,
                    body,
                },
            }
        };
        let body = std::mem::take(&mut stream.body).freeze();
        match &mut event {
            Http2Event::RequestReceived { request, .. } => request.body = body,
            Http2Event::ResponseReceived { response, .. } => response.body = body,
            _ => {}
        }
        stream.remote_closed = true;
        self.events.push_back(event);
        Ok(())
    }
    fn window_update(&mut self, id: u32, increment: u32) -> Result<()> {
        if increment == 0 || increment > 0x7fff_ffff {
            return Err(if id == 0 {
                connection_error(Http2ErrorCode::ProtocolError, "invalid window increment")
            } else {
                stream_error(id, Http2ErrorCode::ProtocolError, "invalid window increment")
            });
        }
        if id == 0 {
            if self.send_window + i64::from(increment) > MAX_FLOW_CONTROL_WINDOW {
                return Err(connection_error(Http2ErrorCode::FlowControlError, "connection window overflow"));
            }
            self.send_window += i64::from(increment);
        } else if let Some(stream) = self.streams.get_mut(&id) {
            if stream.send_window + i64::from(increment) > MAX_FLOW_CONTROL_WINDOW {
                return Err(stream_error(id, Http2ErrorCode::FlowControlError, "stream window overflow"));
            }
            stream.send_window += i64::from(increment);
        } else if self.is_idle(id) {
            return Err(connection_error(Http2ErrorCode::ProtocolError, "WINDOW_UPDATE on idle stream"));
        }
        self.flush_data()
    }
    fn encode_headers(&mut self, id: u32, fields: &[(String, String)], end_stream: bool) -> Result<()> {
        let size = fields.iter().fold(0usize, |size, (name, value)| size.saturating_add(name.len()).saturating_add(value.len()).saturating_add(32));
        if size > self.peer.max_header_list_size as usize {
            return Err(ProtoError::HeaderListTooLarge { size, max: self.peer.max_header_list_size as usize });
        }
        let mut block = BytesMut::new();
        self.encoder.encode(fields, &mut block);
        let bytes = block.freeze();
        let max = self.peer.max_frame_size as usize;
        if bytes.is_empty() {
            return self.queue(Http2Frame::Headers { stream_id: id, end_stream, end_headers: true, header_block: bytes });
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + max).min(bytes.len());
            let header_block = bytes.slice(offset..end);
            let frame = if offset == 0 {
                Http2Frame::Headers { stream_id: id, end_stream, end_headers: end == bytes.len(), header_block }
            } else {
                Http2Frame::Continuation { stream_id: id, end_headers: end == bytes.len(), header_block }
            };
            self.queue(frame)?;
            offset = end;
        }
        Ok(())
    }
    fn flush_data(&mut self) -> Result<()> {
        loop {
            let mut progress = false;
            for (&id, stream) in &mut self.streams {
                if stream.local_closed || !stream.send_started || stream.offset == stream.outgoing.len() {
                    continue;
                }
                let credit = self.send_window.min(stream.send_window).min(i64::from(self.peer.max_frame_size));
                if credit <= 0 {
                    continue;
                }
                let size = (credit as usize).min(stream.outgoing.len() - stream.offset);
                let end = stream.offset + size;
                let end_stream = end == stream.outgoing.len();
                frame::encode_frame(&Http2Frame::Data { stream_id: id, end_stream, data: stream.outgoing.slice(stream.offset..end) }, &mut self.tx)?;
                stream.offset = end;
                stream.send_window -= size as i64;
                self.send_window -= size as i64;
                stream.local_closed = end_stream;
                progress = true;
                if end_stream {
                    stream.outgoing.clear();
                    stream.offset = 0;
                }
            }
            if !progress {
                break;
            }
        }
        self.retire();
        Ok(())
    }
}
#[rustfmt::skip]
fn merged_settings(bytes: &[u8], mut settings: Http2Settings, streams: &BTreeMap<u32, Stream>) -> Result<Option<(Http2Settings, Vec<usize>)>> {
    let initial_window = i64::from(settings.initial_window_size);
    let mut table_sizes = Vec::new();
    if bytes.len() < 9 || bytes[3] != 4 || bytes[4] & 1 != 0 {
        return Ok(None);
    }
    let length = (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
    if bytes.len() < 9 + length || !length.is_multiple_of(6) {
        return Ok(None);
    }
    for item in bytes[9..9 + length].as_chunks::<6>().0 {
        let id = u16::from_be_bytes([item[0], item[1]]);
        let value = u32::from_be_bytes([item[2], item[3], item[4], item[5]]);
        match id {
            1 => { settings.header_table_size = value; table_sizes.push(value as usize); },
            2 => settings.enable_push = value != 0,
            3 => settings.max_concurrent_streams = value,
            4 => {
                if i64::from(value) > MAX_FLOW_CONTROL_WINDOW || streams.values().any(|stream| stream.send_window + i64::from(value) - initial_window > MAX_FLOW_CONTROL_WINDOW) {
                    return Err(connection_error(Http2ErrorCode::FlowControlError, "SETTINGS occurrence overflows stream window"));
                }
                settings.initial_window_size = value;
            },
            5 => settings.max_frame_size = value,
            6 => settings.max_header_list_size = value,
            _ => {}
        }
    }
    Ok(Some((settings, table_sizes)))
}
