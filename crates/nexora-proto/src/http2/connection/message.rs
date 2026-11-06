//! Completed HTTP/2 message validation and event construction.

use super::*;

impl Http2Connection {
    pub(super) fn complete_message(&mut self, id: u32) -> Result<()> {
        let stream = self.streams.get_mut(&id).ok_or_else(|| {
            stream_error(id, Http2ErrorCode::StreamClosed, "message stream closed")
        })?;
        let fields = stream.headers.as_ref().ok_or_else(|| {
            stream_error(id, Http2ErrorCode::ProtocolError, "message has no headers")
        })?;
        let mut headers = Headers::new();
        for (name, value) in fields {
            if !name.starts_with(':') {
                headers.append(name.clone(), value.clone());
            }
        }
        let pseudo = |key: &str| {
            fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        let length = headers.content_length().map_err(|_| {
            stream_error(id, Http2ErrorCode::ProtocolError, "invalid content length")
        })?;
        if self.role == Http2Role::Client
            && pseudo(":status") == Some("205")
            && (!stream.body.is_empty() || length.is_some_and(|size| size != 0))
        {
            return Err(stream_error(
                id,
                Http2ErrorCode::ProtocolError,
                "205 response cannot contain content",
            ));
        }
        let no_body = self.role == Http2Role::Client
            && (stream.state.test(StreamState::HEAD_REQUEST)
                || matches!(pseudo(":status"), Some("204" | "304")));
        if self.role == Http2Role::Client && pseudo(":status") == Some("204") && length.is_some() {
            return Err(stream_error(
                id,
                Http2ErrorCode::ProtocolError,
                "204 response includes content length",
            ));
        }
        if (!no_body && length.is_some_and(|length| length != stream.body.len()))
            || (no_body && !stream.body.is_empty())
        {
            return Err(stream_error(
                id,
                Http2ErrorCode::ProtocolError,
                "message body disagrees with content length or semantics",
            ));
        }
        let body = Bytes::new();
        let mut event = if self.role == Http2Role::Server {
            let method = Method::parse(pseudo(":method").unwrap_or_default()).map_err(|_| {
                stream_error(id, Http2ErrorCode::ProtocolError, "invalid request method")
            })?;
            let authority = pseudo(":authority")
                .or_else(|| headers.get("host"))
                .unwrap_or_default();
            let scheme = pseudo(":scheme").unwrap_or("http");
            let path = match pseudo(":path").unwrap_or("/") {
                "*" => "/*",
                path => path,
            };
            let uri = Uri::parse(&format!("{scheme}://{authority}{path}")).map_err(|_| {
                stream_error(id, Http2ErrorCode::ProtocolError, "invalid request URI")
            })?;
            stream.state = stream.state.patch(
                BitPatch::EMPTY.with_flag(StreamState::HEAD_REQUEST, method == Method::Head),
            );
            self.processed_peer_stream = self.processed_peer_stream.max(id);
            Http2Event::RequestReceived {
                stream_id: id,
                request: Request {
                    method,
                    uri,
                    version: Version::Http2,
                    headers,
                    body,
                },
            }
        } else {
            let status = pseudo(":status")
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| {
                    stream_error(id, Http2ErrorCode::ProtocolError, "missing response status")
                })?;
            Http2Event::ResponseReceived {
                stream_id: id,
                response: Response {
                    status: StatusCode::new(status).map_err(|_| {
                        stream_error(id, Http2ErrorCode::ProtocolError, "invalid response status")
                    })?,
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
        stream.state = stream.state.patch(patch!(StreamState {
            REMOTE_CLOSED: true
        }));
        self.events.push_back(event);
        Ok(())
    }
}
