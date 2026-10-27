//! Incremental HTTP/1 message framing without transport ownership.

use std::fmt::Write;

use super::{
    Http1ClientConfig, Http1KeepAlive, Http1ServerConfig, Method, Request, Response, StatusCode,
    Version,
};
use crate::{Bytes, BytesMut, Headers, ProtoError, Result, Uri};

/// HTTP/1 client encoder and response decoder.
#[derive(Default)]
pub struct Http1ClientCodec {
    config: Http1ClientConfig,
    encode_closed: bool,
    decode_closed: bool,
    head: String,
}

impl std::fmt::Debug for Http1ClientCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1ClientCodec")
            .field("config", &self.config)
            .field("encode_closed", &self.encode_closed)
            .field("decode_closed", &self.decode_closed)
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
        check_open(self.encode_closed || self.decode_closed)?;
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
        write!(head, "{} {target} {version}\r\n", req.method.as_str()).map_err(format_error)?;
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
        self.encode_closed =
            persistence(req.version, &req.headers, false) != Http1KeepAlive::KeepAlive;
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
        check_open(self.decode_closed)?;
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
        let message_framing = framing(&headers, version)?;
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
        let keep_alive = if self.encode_closed && !status.is_informational() && !upgrade {
            Http1KeepAlive::Close
        } else {
            persistence(version, &headers, upgrade)
        };
        let response = Response {
            status,
            version,
            headers,
            body,
        };
        buf.advance(consumed);
        if !status.is_informational() || upgrade {
            self.decode_closed = self.encode_closed || keep_alive != Http1KeepAlive::KeepAlive;
        }
        Ok(Some((response, keep_alive)))
    }
}

/// HTTP/1 server request decoder and response encoder.
#[derive(Default)]
pub struct Http1ServerCodec {
    config: Http1ServerConfig,
    encode_closed: bool,
    decode_closed: bool,
    head: String,
}

impl std::fmt::Debug for Http1ServerCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1ServerCodec")
            .field("config", &self.config)
            .field("encode_closed", &self.encode_closed)
            .field("decode_closed", &self.decode_closed)
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
        check_open(self.decode_closed || self.encode_closed)?;
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
        let request = Request {
            method,
            uri,
            version,
            headers,
            body,
        };
        buf.advance(consumed);
        self.decode_closed = keep_alive != Http1KeepAlive::KeepAlive;
        Ok(Some((request, keep_alive)))
    }

    /// Appends a response using fixed length or chunked framing.
    ///
    /// # Errors
    /// Returns an error for invalid fields, ambiguous framing, configured
    /// limits or a closed or upgraded send direction. Output is unchanged on error.
    pub fn encode_response(&mut self, resp: &Response, out: &mut BytesMut) -> Result<()> {
        check_open(self.encode_closed)?;
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
        write!(
            head,
            "{version} {} {}\r\n",
            resp.status.as_u16(),
            resp.status.reason_phrase()
        )
        .map_err(format_error)?;
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
            self.encode_closed = self.decode_closed
                || persistence(
                    resp.version,
                    &resp.headers,
                    resp.status == StatusCode::SWITCHING_PROTOCOLS,
                ) != Http1KeepAlive::KeepAlive;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Framing {
    Absent,
    Length(usize),
    Chunked,
}

fn protocol(message: &str) -> ProtoError {
    ProtoError::Http1Protocol(message.into())
}

fn check_open(closed: bool) -> Result<()> {
    if closed {
        return Err(protocol("HTTP/1 direction is closed or upgraded"));
    }
    Ok(())
}

fn format_error(error: std::fmt::Error) -> ProtoError {
    protocol(&error.to_string())
}

fn wire_version(version: Version) -> Result<&'static str> {
    match version {
        Version::Http10 | Version::Http11 => Ok(version.as_str()),
        Version::Http2 => Err(ProtoError::InvalidVersion(version.as_str().into())),
    }
}

fn parse_version(version: &str) -> Result<Version> {
    match version {
        "HTTP/1.1" => Ok(Version::Http11),
        "HTTP/1.0" => Ok(Version::Http10),
        _ => Err(ProtoError::InvalidVersion(version.into())),
    }
}

fn check_header_size(size: usize, max: usize) -> Result<()> {
    if size > max {
        return Err(ProtoError::HeaderListTooLarge { size, max });
    }
    Ok(())
}

fn check_body_size(size: usize, max: usize) -> Result<()> {
    if size > max {
        return Err(ProtoError::BodyTooLarge { size, max });
    }
    Ok(())
}

fn find_crlf<const N: usize>(data: &[u8], delimiter: &[u8; N]) -> Option<usize> {
    let mut cursor = 0;
    while let Some(offset) = data[cursor..].iter().position(|byte| *byte == b'\r') {
        let at = cursor + offset;
        if data[at..].starts_with(delimiter) {
            return Some(at);
        }
        cursor = at + 1;
    }
    None
}
fn line_end(data: &[u8]) -> Option<usize> {
    find_crlf(data, b"\r\n")
}

fn parse_head(data: &[u8], max: usize) -> Result<Option<(&str, Headers, usize)>> {
    let Some(end) = find_crlf(data, b"\r\n\r\n") else {
        check_header_size(data.len(), max)?;
        return Ok(None);
    };
    let head_len = end + 4;
    check_header_size(head_len, max)?;
    let head =
        std::str::from_utf8(&data[..end]).map_err(|_| protocol("header block is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or_else(|| protocol("missing start line"))?;
    if first.bytes().any(|byte| byte < b' ' || byte == 127) {
        return Err(protocol("control character in start line"));
    }
    let mut headers = Headers::new();
    for line in lines {
        let (name, value) = parse_field(line)?;
        headers.append(name, value);
    }
    if headers
        .iter()
        .filter(|field| field.name == "host")
        .take(2)
        .count()
        > 1
    {
        return Err(protocol("multiple Host fields"));
    }
    Ok(Some((first, headers, head_len)))
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn validate_value(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| (byte < b' ' && byte != b'\t') || byte == 127)
    {
        return Err(ProtoError::InvalidHeader(
            "control character in header value".into(),
        ));
    }
    Ok(())
}

fn parse_field(line: &str) -> Result<(&str, &str)> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| ProtoError::InvalidHeader("missing field colon".into()))?;
    if name.is_empty() || !name.bytes().all(is_token) {
        return Err(ProtoError::InvalidHeader("invalid field name".into()));
    }
    validate_value(value)?;
    Ok((name, value.trim_matches([' ', '\t'])))
}

fn encode_headers(headers: &Headers, out: &mut String) -> Result<()> {
    for field in headers.iter() {
        if field.name.is_empty() || !field.name.bytes().all(is_token) {
            return Err(ProtoError::InvalidHeader("invalid field name".into()));
        }
        validate_value(&field.value)?;
        write!(out, "{}: {}\r\n", field.name, field.value).map_err(format_error)?;
    }
    if headers
        .iter()
        .filter(|field| field.name == "host")
        .take(2)
        .count()
        > 1
    {
        return Err(protocol("multiple Host fields"));
    }
    if let Some(host) = headers.get("host") {
        validate_authority(host)?;
    }
    Ok(())
}

fn framing(headers: &Headers, version: Version) -> Result<Framing> {
    let lengths = headers.contains("content-length");
    let transfers = headers.contains("transfer-encoding");
    if lengths && transfers {
        return Err(protocol(
            "both Transfer-Encoding and Content-Length present",
        ));
    }
    if transfers {
        if version == Version::Http10 {
            return Err(protocol("HTTP/1.0 does not support Transfer-Encoding"));
        }
        let mut tokens = headers
            .iter()
            .filter(|field| field.name == "transfer-encoding")
            .flat_map(|field| field.value.split(','));
        let first = tokens.next().unwrap_or_default().trim_matches([' ', '\t']);
        if !first.eq_ignore_ascii_case("chunked") || tokens.next().is_some() {
            return Err(protocol("unsupported transfer coding"));
        }
        return Ok(Framing::Chunked);
    }
    let mut length = None;
    for value in headers
        .iter()
        .filter(|field| field.name == "content-length")
        .flat_map(|field| field.value.split(','))
    {
        let value = value.trim_matches([' ', '\t']);
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(protocol("invalid Content-Length"));
        }
        let parsed = value
            .parse::<usize>()
            .map_err(|_| protocol("Content-Length overflow"))?;
        if length.is_some_and(|previous| previous != parsed) {
            return Err(protocol("conflicting Content-Length values"));
        }
        length = Some(parsed);
    }
    Ok(length.map_or(Framing::Absent, Framing::Length))
}

fn append_length(head: &mut String, framing: Framing, size: usize) -> Result<()> {
    match framing {
        Framing::Length(length) if length != size => {
            Err(protocol("Content-Length differs from body length"))
        }
        Framing::Absent => write!(head, "content-length: {size}\r\n").map_err(format_error),
        _ => Ok(()),
    }
}

fn append_message(head: &[u8], body: &[u8], framing: Framing, out: &mut BytesMut) {
    out.extend_from_slice(head);
    if matches!(framing, Framing::Chunked) {
        if !body.is_empty() {
            out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        out.extend_from_slice(body);
    }
}

fn request_uri(method: Method, target: &str, version: Version, headers: &Headers) -> Result<Uri> {
    let host = headers.get("host");
    if version == Version::Http11 && host.is_none_or(str::is_empty) {
        return Err(ProtoError::MissingHeader("host".into()));
    }
    let host = host.unwrap_or("localhost");
    validate_authority(host)?;
    if method == Method::Connect {
        if target.bytes().any(|b| b"/@?#".contains(&b)) || !authority_has_port(target) {
            return Err(ProtoError::InvalidUri(target.into()));
        }
        return Uri::parse(&format!("http://{target}/"));
    }
    if target.split_once("://").is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    }) {
        return Uri::parse(target);
    }
    if !target.starts_with('/') && !(target == "*" && method == Method::Options) {
        return Err(ProtoError::InvalidUri(target.into()));
    }
    Uri::parse(&format!(
        "http://{host}{}",
        if target == "*" { "/*" } else { target }
    ))
}

fn has_token(headers: &Headers, name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case(name))
        .any(|field| {
            field
                .value
                .split(',')
                .any(|part| part.trim_matches([' ', '\t']).eq_ignore_ascii_case(token))
        })
}

fn validate_upgrade_framing(headers: &Headers, framing: Framing, body_size: usize) -> Result<()> {
    if has_token(headers, "upgrade", "websocket")
        && (body_size != 0 || !matches!(framing, Framing::Absent | Framing::Length(0)))
    {
        return Err(protocol("WebSocket upgrade request must not carry a body"));
    }
    Ok(())
}

fn persistence(version: Version, headers: &Headers, upgrade: bool) -> Http1KeepAlive {
    if upgrade {
        Http1KeepAlive::Upgrade
    } else if has_token(headers, "connection", "close")
        || (version == Version::Http10 && !has_token(headers, "connection", "keep-alive"))
    {
        Http1KeepAlive::Close
    } else {
        Http1KeepAlive::KeepAlive
    }
}

fn decode_body(
    data: &[u8],
    offset: usize,
    framing: Framing,
    max_body: usize,
    max_headers: usize,
) -> Result<Option<(Bytes, usize)>> {
    match framing {
        Framing::Absent => Ok(Some((Bytes::new(), offset))),
        Framing::Length(length) => {
            check_body_size(length, max_body)?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| protocol("message length overflow"))?;
            if data.len() < end {
                return Ok(None);
            }
            Ok(Some((Bytes::copy_from_slice(&data[offset..end]), end)))
        }
        Framing::Chunked => decode_chunked(data, offset, max_body, max_headers),
    }
}

fn decode_chunked(
    data: &[u8],
    mut offset: usize,
    max_body: usize,
    max_headers: usize,
) -> Result<Option<(Bytes, usize)>> {
    let mut body = Vec::new();
    let head_size = offset;
    loop {
        let Some(end) = line_end(&data[offset..]) else {
            check_header_size(data.len() - offset, max_headers)?;
            return Ok(None);
        };
        check_header_size(end + 2, max_headers)?;
        let size_line = std::str::from_utf8(&data[offset..offset + end])
            .map_err(|_| chunk_error("invalid size line"))?;
        let (size_text, extension) = size_line
            .split_once(';')
            .map_or((size_line, None), |(s, e)| (s, Some(e)));
        let size_text = size_text.trim_end_matches([' ', '\t']);
        if size_text.is_empty() || !size_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(chunk_error("invalid chunk size"));
        }
        if let Some(extension) = extension {
            validate_chunk_extensions(extension)?;
        }
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| chunk_error("chunk size overflow"))?;
        let total = body
            .len()
            .checked_add(size)
            .ok_or(ProtoError::BodyTooLarge {
                size: usize::MAX,
                max: max_body,
            })?;
        check_body_size(total, max_body)?;
        offset += end + 2;
        if size == 0 {
            let mut metadata_size = head_size;
            loop {
                let Some(end) = line_end(&data[offset..]) else {
                    check_header_size(
                        metadata_size.saturating_add(data.len() - offset),
                        max_headers,
                    )?;
                    return Ok(None);
                };
                if end == 0 {
                    return Ok(Some((Bytes::from(body), offset + 2)));
                }
                metadata_size = metadata_size.saturating_add(end + 2);
                check_header_size(metadata_size, max_headers)?;
                let line = std::str::from_utf8(&data[offset..offset + end])
                    .map_err(|_| chunk_error("invalid trailer text"))?;
                let (name, _) = parse_field(line)?;
                if [
                    "content-length",
                    "transfer-encoding",
                    "host",
                    "connection",
                    "upgrade",
                ]
                .iter()
                .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
                {
                    return Err(chunk_error("forbidden framing trailer"));
                }
                offset += end + 2;
            }
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| chunk_error("chunk length overflow"))?;
        let after = end
            .checked_add(2)
            .ok_or_else(|| chunk_error("chunk length overflow"))?;
        if data.len() < after {
            return Ok(None);
        }
        if &data[end..after] != b"\r\n" {
            return Err(chunk_error("missing chunk data terminator"));
        }
        body.extend_from_slice(&data[offset..end]);
        offset = after;
    }
}

fn chunk_error(message: &str) -> ProtoError {
    ProtoError::InvalidChunkedEncoding(message.into())
}

fn validate_status_framing(status: StatusCode, framing: Framing) -> Result<()> {
    if status.as_u16() == 205 && matches!(framing, Framing::Length(length) if length != 0) {
        return Err(protocol("Reset Content response cannot contain content"));
    }
    if (status.is_informational() || status == StatusCode::NO_CONTENT)
        && !matches!(framing, Framing::Absent)
    {
        return Err(protocol(
            "status forbids Content-Length and Transfer-Encoding",
        ));
    }
    Ok(())
}

fn validate_authority(authority: &str) -> Result<()> {
    if authority.is_empty() || authority.bytes().any(|b| b"/@?#".contains(&b)) {
        return Err(ProtoError::InvalidHeader("invalid Host authority".into()));
    }
    crate::uri::validate_authority(authority)
        .map_err(|_| ProtoError::InvalidHeader("invalid Host authority".into()))
}

fn authority_has_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        authority
            .split_once(']')
            .is_some_and(|(_, suffix)| suffix.starts_with(':'))
    } else {
        authority.contains(':')
    }
}

fn validate_chunk_extensions(extension: &str) -> Result<()> {
    let mut remaining = extension.as_bytes();
    loop {
        remaining = trim_ows(remaining);
        let name_len = remaining.iter().take_while(|byte| is_token(**byte)).count();
        if name_len == 0 {
            return Err(chunk_error("invalid extension name"));
        }
        remaining = trim_ows(&remaining[name_len..]);
        if remaining.first() == Some(&b'=') {
            remaining = trim_ows(&remaining[1..]);
            if remaining.first() == Some(&b'"') {
                remaining = &remaining[1..];
                loop {
                    let Some((&byte, rest)) = remaining.split_first() else {
                        return Err(chunk_error("unterminated quoted extension"));
                    };
                    remaining = rest;
                    if byte == b'"' {
                        break;
                    }
                    if byte == b'\\' {
                        let Some((&escaped, rest)) = remaining.split_first() else {
                            return Err(chunk_error("incomplete quoted extension escape"));
                        };
                        if (escaped < b' ' && escaped != b'\t') || escaped == 127 {
                            return Err(chunk_error("invalid quoted extension escape"));
                        }
                        remaining = rest;
                    } else if (byte < b' ' && byte != b'\t') || byte == 127 {
                        return Err(chunk_error("invalid quoted extension"));
                    }
                }
            } else {
                let value_len = remaining.iter().take_while(|byte| is_token(**byte)).count();
                if value_len == 0 {
                    return Err(chunk_error("missing extension value"));
                }
                remaining = &remaining[value_len..];
            }
        }
        remaining = trim_ows(remaining);
        if remaining.is_empty() {
            return Ok(());
        }
        if remaining.first() != Some(&b';') {
            return Err(chunk_error("invalid extension separator"));
        }
        remaining = &remaining[1..];
    }
}

fn trim_ows(mut input: &[u8]) -> &[u8] {
    while input
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        input = &input[1..];
    }
    input
}
