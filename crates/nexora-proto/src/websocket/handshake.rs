use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha1::{Digest, Sha1};

use crate::{
    ProtoError, Result,
    headers::Headers,
    http1::{Method, Request, Response, StatusCode, Version},
    uri::Uri,
};

const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Constructs and validates HTTP/1.1 WebSocket upgrade handshakes.
pub struct WebSocketHandshake;

impl WebSocketHandshake {
    /// Derives a Base64-encoded 16-byte nonce from a seed.
    ///
    /// The caller must supply a fresh, unpredictable seed for each connection.
    /// This deterministic function does not collect operating-system entropy.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn generate_key(seed: u64) -> String {
        let nonce = Sha1::digest(seed.to_be_bytes());
        STANDARD.encode(&nonce[..16])
    }

    /// Computes the RFC 6455 SHA-1 and Base64 accept value.
    ///
    /// # Errors
    ///
    /// This function does not return errors or validate the client nonce.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn compute_accept_key(client_key: &str) -> String {
        let mut hash = Sha1::new();
        hash.update(client_key.as_bytes());
        hash.update(ACCEPT_GUID);
        STANDARD.encode(hash.finalize())
    }

    /// Constructs a GET upgrade, preserving extra headers except framing fields.
    ///
    /// Required handshake fields replace any corresponding extra headers.
    /// Body framing is omitted because an upgrade request has no HTTP body.
    ///
    /// # Errors
    ///
    /// This function does not return errors. The supplied key and extra headers
    /// must be valid HTTP header values.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn build_upgrade_request(uri: &Uri, sec_key: &str, extra_headers: &Headers) -> Request {
        let mut request = Request::new(Method::Get, uri.clone());
        for field in extra_headers.iter() {
            if !is_owned_header(&field.name) {
                request.headers.append(&field.name, &field.value);
            }
        }
        request.headers.insert("host", uri.authority());
        request.headers.insert("upgrade", "websocket");
        request.headers.insert("connection", "Upgrade");
        request.headers.insert("sec-websocket-version", "13");
        request.headers.insert("sec-websocket-key", sec_key);
        request.version = Version::Http11;
        request
    }

    /// Validates a server-side upgrade and returns its client nonce.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for invalid methods, versions, upgrade tokens,
    /// duplicate security headers, malformed nonces, or HTTP body framing.
    /// Returns a missing-header error when a required field is absent.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn validate_upgrade_request(req: &Request) -> Result<String> {
        if req.method != Method::Get || req.version != Version::Http11 {
            return Err(protocol("an upgrade requires GET and HTTP/1.1"));
        }
        validate_headers(&req.headers)?;
        let host = singleton(&req.headers, "host")?;
        if host.contains(['/', '?', '#']) || Uri::parse(&format!("http://{host}/")).is_err() {
            return Err(protocol("Host must be a valid authority"));
        }
        require_token(&req.headers, "upgrade", "websocket")?;
        require_token(&req.headers, "connection", "upgrade")?;
        if singleton(&req.headers, "sec-websocket-version")? != "13" {
            return Err(protocol("Sec-WebSocket-Version must be 13"));
        }
        let key = singleton(&req.headers, "sec-websocket-key")?;
        validate_key(key)?;
        validate_offers(&req.headers)?;
        validate_empty_body(&req.headers, req.body.is_empty())?;
        Ok(key.to_owned())
    }

    /// Constructs a successful upgrade response for a previously validated key.
    ///
    /// # Errors
    ///
    /// This function does not return errors or validate the client nonce.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn build_upgrade_response(client_key: &str) -> Response {
        let mut response = Response::new(StatusCode::SWITCHING_PROTOCOLS);
        response.version = Version::Http11;
        response.headers.insert("upgrade", "websocket");
        response.headers.insert("connection", "Upgrade");
        response
            .headers
            .insert("sec-websocket-accept", Self::compute_accept_key(client_key));
        response
    }

    /// Validates a client-side upgrade against the original request nonce.
    ///
    /// Extensions and subprotocol negotiation are unsupported by this validator.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for a failed status, invalid upgrade fields,
    /// duplicate accept headers, mismatched accept values, HTTP body framing,
    /// or an unsupported negotiated extension or subprotocol. Returns a
    /// missing-header error when a required field is absent.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn validate_upgrade_response(resp: &Response, expected_client_key: &str) -> Result<()> {
        if resp.status != StatusCode::SWITCHING_PROTOCOLS || resp.version != Version::Http11 {
            return Err(protocol("an upgrade requires status 101 and HTTP/1.1"));
        }
        validate_headers(&resp.headers)?;
        validate_key(expected_client_key)?;
        require_token(&resp.headers, "upgrade", "websocket")?;
        require_token(&resp.headers, "connection", "upgrade")?;
        let accept = singleton(&resp.headers, "sec-websocket-accept")?;
        if accept != Self::compute_accept_key(expected_client_key) {
            return Err(protocol("Sec-WebSocket-Accept does not match the request"));
        }
        if resp.headers.contains("sec-websocket-extensions")
            || resp.headers.contains("sec-websocket-protocol")
        {
            return Err(protocol(
                "negotiated extensions and subprotocols are unsupported",
            ));
        }
        if resp.headers.contains("content-length") {
            return Err(protocol("status 101 forbids Content-Length"));
        }
        validate_empty_body(&resp.headers, resp.body.is_empty())
    }
}

fn protocol(reason: &str) -> ProtoError {
    ProtoError::WebSocketProtocol(reason.to_owned())
}

fn validate_offers(headers: &Headers) -> Result<()> {
    let mut protocols = Vec::new();
    for field in headers.iter() {
        if field.name.eq_ignore_ascii_case("sec-websocket-protocol") {
            for token in field
                .value
                .split(',')
                .map(|value| value.trim_matches([' ', '\t']))
            {
                if !valid_token(token) || protocols.contains(&token) {
                    return Err(protocol("invalid or duplicate subprotocol offer"));
                }
                protocols.push(token);
            }
        } else if field.name.eq_ignore_ascii_case("sec-websocket-extensions") {
            for extension in field.value.split(',') {
                let mut parts = extension
                    .split(';')
                    .map(|value| value.trim_matches([' ', '\t']));
                if !parts.next().is_some_and(valid_token) {
                    return Err(protocol("invalid extension offer"));
                }
                for parameter in parts {
                    let (name, value) = parameter
                        .split_once('=')
                        .map_or((parameter, None), |(name, value)| (name, Some(value)));
                    if !valid_token(name.trim_matches([' ', '\t']))
                        || value
                            .is_some_and(|value| !valid_parameter(value.trim_matches([' ', '\t'])))
                    {
                        return Err(protocol("invalid extension parameter"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn valid_parameter(value: &str) -> bool {
    if !value.starts_with('"') {
        return valid_token(value);
    }
    let Some(quoted) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return false;
    };
    // RFC 6455 requires the unescaped quoted value to satisfy the token grammar.
    let mut bytes = quoted.bytes();
    let mut nonempty = false;
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'\\' {
            let Some(escaped) = bytes.next() else {
                return false;
            };
            escaped
        } else {
            byte
        };
        if !is_token_byte(byte) {
            return false;
        }
        nonempty = true;
    }
    nonempty
}

fn is_owned_header(name: &str) -> bool {
    [
        "host",
        "upgrade",
        "connection",
        "sec-websocket-version",
        "sec-websocket-key",
        "sec-websocket-accept",
        "content-length",
        "transfer-encoding",
    ]
    .iter()
    .any(|owned| name.eq_ignore_ascii_case(owned))
}

fn singleton<'a>(headers: &'a Headers, name: &str) -> Result<&'a str> {
    let mut values = headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case(name));
    let value = values
        .next()
        .ok_or_else(|| ProtoError::MissingHeader(name.to_owned()))?;
    if values.next().is_some() {
        return Err(protocol("duplicate singleton handshake header"));
    }
    Ok(value.value.trim_matches([' ', '\t']))
}

fn validate_key(key: &str) -> Result<()> {
    let decoded = STANDARD
        .decode(key)
        .map_err(|_| protocol("Sec-WebSocket-Key must be canonical Base64"))?;
    if decoded.len() != 16 {
        return Err(protocol("Sec-WebSocket-Key must encode exactly 16 bytes"));
    }
    Ok(())
}

fn validate_headers(headers: &Headers) -> Result<()> {
    for field in headers.iter() {
        if field.name.is_empty() || !field.name.bytes().all(is_token_byte) {
            return Err(protocol("invalid HTTP header name in upgrade"));
        }
        if field
            .value
            .bytes()
            .any(|byte| byte == 0x7f || (byte < 0x20 && byte != b'\t'))
        {
            return Err(protocol("invalid HTTP header value in upgrade"));
        }
    }
    Ok(())
}

fn require_token(headers: &Headers, name: &str, required: &str) -> Result<()> {
    let mut present = false;
    let mut found = false;
    for field in headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case(name))
    {
        present = true;
        for token in field.value.split(',') {
            let token = token.trim_matches([' ', '\t']);
            let valid = if name == "upgrade" {
                let mut parts = token.split('/');
                parts.next().is_some_and(valid_token)
                    && parts.next().is_none_or(valid_token)
                    && parts.next().is_none()
            } else {
                valid_token(token)
            };
            if !valid {
                return Err(protocol("invalid token list in upgrade header"));
            }
            found |= token.eq_ignore_ascii_case(required);
        }
    }
    if !present {
        return Err(ProtoError::MissingHeader(name.to_owned()));
    }
    if !found {
        return Err(protocol("required upgrade token is missing"));
    }
    Ok(())
}

fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(is_token_byte)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn validate_empty_body(headers: &Headers, body_empty: bool) -> Result<()> {
    if !body_empty || headers.contains("transfer-encoding") {
        return Err(protocol("an upgrade must not carry an HTTP body"));
    }
    if let Some(length) = headers.content_length()?
        && length != 0
    {
        return Err(protocol("an upgrade must not declare an HTTP body"));
    }
    Ok(())
}
