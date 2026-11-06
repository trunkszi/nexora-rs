use super::*;

#[derive(Clone, Copy)]
pub(super) enum Framing {
    Absent,
    Length(usize),
    Chunked,
}

#[cold_sink]
pub(super) fn protocol(message: &str) -> ProtoError {
    ProtoError::Http1Protocol(message.into())
}

#[hot_inline]
pub(super) fn check_open(closed: bool) -> Result<()> {
    if closed {
        return Err(protocol("HTTP/1 direction is closed or upgraded"));
    }
    Ok(())
}

#[cold_sink]
pub(super) fn format_error(error: std::fmt::Error) -> ProtoError {
    protocol(&error.to_string())
}

pub(super) fn wire_version(version: Version) -> Result<&'static str> {
    match version {
        Version::Http10 | Version::Http11 => Ok(version.as_str()),
        Version::Http2 => Err(invalid_version(version.as_str())),
    }
}

pub(super) fn parse_version(version: &str) -> Result<Version> {
    match version {
        "HTTP/1.1" => Ok(Version::Http11),
        "HTTP/1.0" => Ok(Version::Http10),
        _ => Err(invalid_version(version)),
    }
}

#[inline]
pub(super) fn check_header_size(size: usize, max: usize) -> Result<()> {
    if size > max {
        return Err(crate::error::header_limit(size, max));
    }
    Ok(())
}

#[inline]
pub(super) fn check_body_size(size: usize, max: usize) -> Result<()> {
    if size > max {
        return Err(crate::error::body_limit(size, max));
    }
    Ok(())
}

#[inline]
pub(super) fn find_crlf<const N: usize>(data: &[u8], delimiter: &[u8; N]) -> Option<usize> {
    let mut cursor = 0;
    while let Some(offset) = find_cr(&data[cursor..]) {
        let at = cursor + offset;
        if data[at..].starts_with(delimiter) {
            return Some(at);
        }
        cursor = at + 1;
    }
    None
}
#[inline]
pub(super) fn line_end(data: &[u8]) -> Option<usize> {
    find_crlf(data, b"\r\n")
}

pub(super) fn parse_head(data: &[u8], max: usize) -> Result<Option<(&str, Headers, usize)>> {
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

pub(super) fn validate_value(value: &str) -> Result<()> {
    if !all_bytes(value.as_bytes(), is_field_value) {
        return Err(crate::error::invalid_header(
            "control character in header value",
        ));
    }
    Ok(())
}

pub(super) fn parse_field(line: &str) -> Result<(&str, &str)> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| crate::error::invalid_header("missing field colon"))?;
    if name.is_empty() || !all_bytes(name.as_bytes(), is_token) {
        return Err(crate::error::invalid_header("invalid field name"));
    }
    validate_value(value)?;
    Ok((name, value.trim_matches([' ', '\t'])))
}

pub(super) fn encode_headers(headers: &Headers, out: &mut String) -> Result<()> {
    for field in headers.iter() {
        if field.name.is_empty() || !all_bytes(field.name.as_bytes(), is_token) {
            return Err(crate::error::invalid_header("invalid field name"));
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

pub(super) fn framing(headers: &Headers, version: Version) -> Result<Framing> {
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
        if value.is_empty() || !all_bytes(value.as_bytes(), |byte| byte.is_ascii_digit()) {
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

pub(super) fn append_length(head: &mut String, framing: Framing, size: usize) -> Result<()> {
    match framing {
        Framing::Length(length) if length != size => {
            Err(protocol("Content-Length differs from body length"))
        }
        Framing::Absent => write!(head, "content-length: {size}\r\n").map_err(format_error),
        _ => Ok(()),
    }
}

pub(super) fn append_message(head: &[u8], body: &[u8], framing: Framing, out: &mut BytesMut) {
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

pub(super) fn request_uri(
    method: Method,
    target: &str,
    version: Version,
    headers: &Headers,
) -> Result<Uri> {
    let host = headers.get("host");
    if version == Version::Http11 && host.is_none_or(str::is_empty) {
        return Err(missing_host());
    }
    let host = host.unwrap_or("localhost");
    validate_authority(host)?;
    if method == Method::Connect {
        if target.bytes().any(|b| b"/@?#".contains(&b)) || !authority_has_port(target) {
            return Err(invalid_uri(target));
        }
        return Uri::parse(&format!("http://{target}/"));
    }
    if target.split_once("://").is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    }) {
        return Uri::parse(target);
    }
    if !target.starts_with('/') && !(target == "*" && method == Method::Options) {
        return Err(invalid_uri(target));
    }
    Uri::parse(&format!(
        "http://{host}{}",
        if target == "*" { "/*" } else { target }
    ))
}

pub(super) fn has_token(headers: &Headers, name: &str, token: &str) -> bool {
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

pub(super) fn validate_upgrade_framing(
    headers: &Headers,
    framing: Framing,
    body_size: usize,
) -> Result<()> {
    if has_token(headers, "upgrade", "websocket")
        && (body_size != 0 || !matches!(framing, Framing::Absent | Framing::Length(0)))
    {
        return Err(protocol("WebSocket upgrade request must not carry a body"));
    }
    Ok(())
}

pub(super) fn persistence(version: Version, headers: &Headers, upgrade: bool) -> Http1KeepAlive {
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

pub(super) fn decode_body(
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

pub(super) fn decode_chunked(
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
            .ok_or_else(|| crate::error::body_limit(usize::MAX, max_body))?;
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

#[cold_sink]
pub(super) fn chunk_error(message: &str) -> ProtoError {
    ProtoError::InvalidChunkedEncoding(message.into())
}

pub(super) fn validate_status_framing(status: StatusCode, framing: Framing) -> Result<()> {
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

pub(super) fn validate_authority(authority: &str) -> Result<()> {
    if authority.is_empty() || authority.bytes().any(|b| b"/@?#".contains(&b)) {
        return Err(crate::error::invalid_header("invalid Host authority"));
    }
    crate::uri::validate_authority(authority)
        .map_err(|_| crate::error::invalid_header("invalid Host authority"))
}

pub(super) fn authority_has_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        authority
            .split_once(']')
            .is_some_and(|(_, suffix)| suffix.starts_with(':'))
    } else {
        authority.contains(':')
    }
}

#[cold_sink]
pub(super) fn invalid_version(version: &str) -> ProtoError {
    ProtoError::InvalidVersion(version.into())
}
#[cold_sink]
pub(super) fn invalid_uri(target: &str) -> ProtoError {
    ProtoError::InvalidUri(target.into())
}
#[cold_sink]
pub(super) fn missing_host() -> ProtoError {
    ProtoError::MissingHeader("host".into())
}
