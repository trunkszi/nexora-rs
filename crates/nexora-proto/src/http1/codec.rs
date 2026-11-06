//! Incremental HTTP/1 message framing without transport ownership.

use std::fmt::Write;

use uarch::prelude::*;

use crate::scan::{all_bytes, is_field_value, is_token};

mod state;
use state::Http1StateWord;

mod scan;
mod validation;
use scan::find_cr;
use validation::validate_chunk_extensions;

use super::{
    Http1ClientConfig, Http1KeepAlive, Http1ServerConfig, Method, Request, Response, StatusCode,
    Version,
};
use crate::{Bytes, BytesMut, Headers, ProtoError, Result, Uri};

/// HTTP/1 client encoder and response decoder.
#[derive(Default)]
pub struct Http1ClientCodec {
    config: Http1ClientConfig,
    state: Http1StateWord,
    head: String,
}

impl std::fmt::Debug for Http1ClientCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1ClientCodec")
            .field("config", &self.config)
            .field("encode_closed", &self.state.encode_closed())
            .field("decode_closed", &self.state.decode_closed())
            .finish()
    }
}

impl Http1ClientCodec {
    /// Creates a codec with bounded header and body reassembly.
    pub fn new(config: Http1ClientConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Appends a complete request, generating missing Host and length headers.
    /// CONNECT uses the URI authority; OPTIONS with path `/*` uses target `*`.
    ///
    /// # Errors
    /// Returns an error for invalid fields, ambiguous framing, configured limits,
    /// or a closed or upgraded direction.
    /// The output remains unchanged on error.
    pub fn encode_request(&mut self, req: &Request, out: &mut BytesMut) -> Result<()> {
        check_open(self.state.either_closed())?;
        check_body_size(req.body.len(), self.config.max_request_body_size)?;
        let version = wire_version(req.version)?;
        let authority;
        let target = if req.method == Method::Connect {
            let uri_authority = req.uri.authority();
            authority = if authority_has_port(&uri_authority) {
                uri_authority
            } else {
                format!("{uri_authority}:{}", req.uri.port())
            };
            authority.as_str()
        } else if req.method == Method::Options && req.uri.path_and_query() == "/*" {
            "*"
        } else {
            req.uri.path_and_query()
        };
        if target.is_empty() || target.bytes().any(|byte| byte <= b' ' || byte == 127) {
            return Err(protocol("invalid request target"));
        }
        self.head.clear();
        let head = &mut self.head;
        head.push_str(req.method.as_str());
        head.push(' ');
        head.push_str(target);
        head.push(' ');
        head.push_str(version);
        head.push_str("\r\n");
        encode_headers(&req.headers, head)?;
        if !req.headers.contains("host") {
            let authority = req.uri.authority_str();
            validate_value(authority)?;
            write!(head, "host: {authority}\r\n").map_err(format_error)?;
        }
        let framing = framing(&req.headers, req.version)?;
        validate_upgrade_framing(&req.headers, framing, req.body.len())?;
        append_length(head, framing, req.body.len())?;
        head.push_str("\r\n");
        check_header_size(head.len(), self.config.max_header_list_size)?;
        append_message(head.as_bytes(), req.body.as_ref(), framing, out);
        self.state.close_encode(
            persistence(req.version, &req.headers, false) != Http1KeepAlive::KeepAlive,
        );
        self.state.message(
            &req.headers,
            framing,
            persistence(req.version, &req.headers, false),
            req.method == Method::Head,
        );
        Ok(())
    }

    /// Decodes one response, leaving incomplete input and following messages intact.
    ///
    /// # Errors
    /// Returns an error for malformed framing, configured size limits or a closed
    /// or upgraded receive direction. Input is
    /// unchanged on error. Responses requiring transport EOF are rejected because
    /// this interface has no EOF notification.
    pub fn decode_response(
        &mut self,
        buf: &mut BytesMut,
        request_method: Method,
    ) -> Result<Option<(Response, Http1KeepAlive)>> {
        check_open(self.state.decode_closed())?;
        let Some((line, headers, head_len)) =
            parse_head(buf.as_ref(), self.config.max_header_list_size)?
        else {
            return Ok(None);
        };
        let mut parts = line.splitn(3, ' ');
        let version = parse_version(parts.next().unwrap_or_default())?;
        let code = parts.next().unwrap_or_default();
        if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(protocol("invalid status line"));
        }
        let status = StatusCode::new(code.parse().map_err(|_| protocol("invalid status"))?)?;
        let reason = parts
            .next()
            .ok_or_else(|| protocol("missing status reason separator"))?;
        validate_value(reason)?;
        let message_framing = if request_method == Method::Connect && status.is_success() {
            // Successful CONNECT ends HTTP framing at the header terminator.
            Framing::Absent
        } else {
            framing(&headers, version)?
        };
        validate_status_framing(status, message_framing)?;
        let upgrade = status == StatusCode::SWITCHING_PROTOCOLS
            || (request_method == Method::Connect && status.is_success());
        let bodyless = request_method == Method::Head
            || status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status.as_u16() == 304
            || upgrade;
        let (body, consumed) = if bodyless {
            (Bytes::new(), head_len)
        } else {
            if matches!(message_framing, Framing::Absent) {
                return Err(protocol("response requires EOF-delimited body"));
            }
            let Some(body) = decode_body(
                buf.as_ref(),
                head_len,
                message_framing,
                self.config.max_body_size,
                self.config.max_header_list_size,
            )?
            else {
                return Ok(None);
            };
            body
        };
        if status.as_u16() == 205 && !body.is_empty() {
            return Err(protocol("Reset Content response cannot contain content"));
        }
        let keep_alive = if self.state.encode_closed() && !status.is_informational() && !upgrade {
            Http1KeepAlive::Close
        } else {
            persistence(version, &headers, upgrade)
        };
        self.state.message(
            &headers,
            message_framing,
            keep_alive,
            request_method == Method::Head,
        );
        let keep_alive = self.state.persistence();
        let response = Response {
            status,
            version,
            headers,
            body,
        };
        buf.advance(consumed);
        if !status.is_informational() || upgrade {
            self.state.close_decode(
                self.state.encode_closed() || keep_alive != Http1KeepAlive::KeepAlive,
            );
        }
        Ok(Some((response, keep_alive)))
    }
}

/// HTTP/1 server request decoder and response encoder.
#[derive(Default)]
pub struct Http1ServerCodec {
    config: Http1ServerConfig,
    state: Http1StateWord,
    head: String,
}

impl std::fmt::Debug for Http1ServerCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1ServerCodec")
            .field("config", &self.config)
            .field("encode_closed", &self.state.encode_closed())
            .field("decode_closed", &self.state.decode_closed())
            .finish()
    }
}

impl Http1ServerCodec {
    /// Creates a codec with bounded header and body reassembly.
    pub fn new(config: Http1ServerConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Decodes one request and preserves pipelined or upgraded bytes.
    /// Origin-form targets use Host as the URI authority. OPTIONS target `*`
    /// maps to path `/*`; CONNECT authority maps to an absolute URI with path `/`.
    ///
    /// # Errors
    /// Returns an error for malformed messages, ambiguous framing, configured
    /// limits or a closed or upgraded direction. Input remains unchanged on errors
    /// and incomplete messages. An upgrade request cannot carry a framed body.
    pub fn decode_request(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Option<(Request, Http1KeepAlive)>> {
        check_open(self.state.either_closed())?;
        let Some((line, headers, head_len)) =
            parse_head(buf.as_ref(), self.config.max_header_list_size)?
        else {
            return Ok(None);
        };
        let mut parts = line.split(' ');
        let method = Method::parse(parts.next().unwrap_or_default())?;
        let target = parts
            .next()
            .ok_or_else(|| protocol("missing request target"))?;
        let version = parse_version(parts.next().unwrap_or_default())?;
        if parts.next().is_some()
            || target.is_empty()
            || target.bytes().any(|b| b <= b' ' || b == 127 || b == b'#')
        {
            return Err(protocol("invalid request line"));
        }
        let uri = request_uri(method, target, version, &headers)?;
        let message_framing = framing(&headers, version)?;
        validate_upgrade_framing(&headers, message_framing, 0)?;
        let upgrade = has_token(&headers, "upgrade", "websocket");
        let (body, consumed) = if upgrade {
            (Bytes::new(), head_len)
        } else {
            let Some(body) = decode_body(
                buf.as_ref(),
                head_len,
                message_framing,
                self.config.max_body_size,
                self.config.max_header_list_size,
            )?
            else {
                return Ok(None);
            };
            body
        };
        let keep_alive = persistence(version, &headers, upgrade);
        self.state
            .message(&headers, message_framing, keep_alive, false);
        let keep_alive = self.state.persistence();
        let request = Request {
            method,
            uri,
            version,
            headers,
            body,
        };
        buf.advance(consumed);
        self.state
            .close_decode(keep_alive != Http1KeepAlive::KeepAlive);
        Ok(Some((request, keep_alive)))
    }

    /// Appends a response using fixed length or chunked framing.
    ///
    /// # Errors
    /// Returns an error for invalid fields, ambiguous framing, configured
    /// limits or a closed or upgraded send direction. Output is unchanged on error.
    pub fn encode_response(&mut self, resp: &Response, out: &mut BytesMut) -> Result<()> {
        check_open(self.state.encode_closed())?;
        check_body_size(resp.body.len(), self.config.max_body_size)?;
        let version = wire_version(resp.version)?;
        StatusCode::new(resp.status.as_u16())?;
        let bodyless = resp.status.is_informational()
            || resp.status == StatusCode::NO_CONTENT
            || resp.status.as_u16() == 304;
        if (bodyless || resp.status.as_u16() == 205) && !resp.body.is_empty() {
            return Err(protocol("status does not permit a response body"));
        }
        self.head.clear();
        let head = &mut self.head;
        head.push_str(version);
        head.push(' ');
        let code = resp.status.as_u16();
        for digit in [code / 100, code / 10 % 10, code % 10] {
            head.push(char::from(b'0' + digit as u8));
        }
        head.push(' ');
        head.push_str(resp.status.reason_phrase());
        head.push_str("\r\n");
        encode_headers(&resp.headers, head)?;
        let message_framing = framing(&resp.headers, resp.version)?;
        validate_status_framing(resp.status, message_framing)?;
        if !bodyless {
            append_length(head, message_framing, resp.body.len())?;
        }
        head.push_str("\r\n");
        check_header_size(head.len(), self.config.max_header_list_size)?;
        append_message(
            head.as_bytes(),
            resp.body.as_ref(),
            if bodyless {
                Framing::Absent
            } else {
                message_framing
            },
            out,
        );
        if !resp.status.is_informational() || resp.status == StatusCode::SWITCHING_PROTOCOLS {
            self.state.close_encode(
                self.state.decode_closed()
                    || persistence(
                        resp.version,
                        &resp.headers,
                        resp.status == StatusCode::SWITCHING_PROTOCOLS,
                    ) != Http1KeepAlive::KeepAlive,
            );
        }
        self.state.message(
            &resp.headers,
            message_framing,
            persistence(
                resp.version,
                &resp.headers,
                resp.status == StatusCode::SWITCHING_PROTOCOLS,
            ),
            false,
        );
        Ok(())
    }
}

mod framing;
use framing::*;
