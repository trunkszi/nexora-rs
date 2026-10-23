//! HTTP message types and incremental HTTP/1 codecs.

mod codec;

pub use codec::{Http1ClientCodec, Http1ServerCodec};

use crate::{Bytes, Headers, ProtoError, Result, Uri};

/// Supported HTTP request methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Method {
    #[default]
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
}

impl Method {
    /// Returns the case-sensitive wire token.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
        }
    }

    /// Parses a case-sensitive supported HTTP method token.
    ///
    /// # Errors
    /// Returns [`ProtoError::InvalidMethod`] for an unsupported token.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            "HEAD" => Ok(Self::Head),
            "OPTIONS" => Ok(Self::Options),
            "PATCH" => Ok(Self::Patch),
            "CONNECT" => Ok(Self::Connect),
            "TRACE" => Ok(Self::Trace),
            _ => Err(ProtoError::InvalidMethod(s.into())),
        }
    }
}

/// HTTP protocol version attached to a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Version {
    #[default]
    Http11,
    Http10,
    Http2,
}

impl Version {
    /// Returns the textual HTTP version identifier.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http11 => "HTTP/1.1",
            Self::Http10 => "HTTP/1.0",
            Self::Http2 => "HTTP/2.0",
        }
    }
}

/// HTTP status code; [`Self::new`] validates the supported numeric range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const NO_CONTENT: Self = Self(204);
    pub const SWITCHING_PROTOCOLS: Self = Self(101);
    pub const MOVED_PERMANENTLY: Self = Self(301);
    pub const FOUND: Self = Self(302);
    pub const SEE_OTHER: Self = Self(303);
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    pub const PERMANENT_REDIRECT: Self = Self(308);
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const BAD_GATEWAY: Self = Self(502);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    pub const GATEWAY_TIMEOUT: Self = Self(504);

    /// Creates a status code in the range `100..=599`.
    ///
    /// # Errors
    /// Returns [`ProtoError::InvalidStatusCode`] outside that range.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn new(code: u16) -> Result<Self> {
        if code >= 100 && code <= 599 {
            Ok(Self(code))
        } else {
            Err(ProtoError::InvalidStatusCode(code))
        }
    }

    /// Returns the numeric status code.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns a conventional reason phrase, or an empty string for unknown codes.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn reason_phrase(self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            103 => "Early Hints",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            208 => "Already Reported",
            226 => "IM Used",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            421 => "Misdirected Request",
            422 => "Unprocessable Content",
            423 => "Locked",
            424 => "Failed Dependency",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",
            _ => "",
        }
    }

    /// Returns whether this code belongs to the informational class.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn is_informational(self) -> bool {
        self.0 >= 100 && self.0 < 200
    }

    /// Returns whether this code belongs to the success class.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// Returns whether this code belongs to the redirection class.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn is_redirection(self) -> bool {
        self.0 >= 300 && self.0 < 400
    }

    /// Returns whether this code belongs to the client-error class.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn is_client_error(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    /// Returns whether this code belongs to the server-error class.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn is_server_error(self) -> bool {
        self.0 >= 500 && self.0 < 600
    }
}

/// An HTTP request with a complete body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: Headers,
    pub body: Bytes,
}

impl Request {
    /// Creates an HTTP/1.1 request with empty headers and body.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            version: Version::Http11,
            headers: Headers::new(),
            body: Bytes::new(),
        }
    }

    /// Creates a GET request by parsing a URI.
    ///
    /// # Errors
    /// Returns [`ProtoError::InvalidUri`] if the URI is invalid.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn get(uri: &str) -> Result<Self> {
        Ok(Self::new(Method::Get, Uri::parse(uri)?))
    }

    /// Creates a POST request by parsing a URI and attaching a body.
    ///
    /// # Errors
    /// Returns [`ProtoError::InvalidUri`] if the URI is invalid.
    ///
    /// # Panics
    /// This function does not panic unless the supplied conversion panics.
    pub fn post(uri: &str, body: impl Into<Bytes>) -> Result<Self> {
        Ok(Self::new(Method::Post, Uri::parse(uri)?).with_body(body))
    }

    /// Inserts a header, replacing existing values with the same name.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic unless a supplied conversion panics.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Replaces the request body.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic unless the supplied conversion panics.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Returns the URI path without its query string.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// Returns the first header value for a case-insensitive name.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }
}

/// An HTTP response with a complete body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: StatusCode,
    pub version: Version,
    pub headers: Headers,
    pub body: Bytes,
}

impl Response {
    /// Creates an HTTP/1.1 response with empty headers and body.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            version: Version::Http11,
            headers: Headers::new(),
            body: Bytes::new(),
        }
    }

    /// Creates a successful response with the supplied body.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic unless the supplied conversion panics.
    pub fn ok(body: impl Into<Bytes>) -> Self {
        Self::new(StatusCode::OK).with_body(body)
    }

    /// Creates a response with the JSON media type and supplied encoded body.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic unless the supplied conversion panics.
    pub fn json(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self::new(status)
            .with_header("content-type", "application/json")
            .with_body(body)
    }

    /// Creates a response with the UTF-8 plain-text media type.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic unless the supplied conversion panics.
    pub fn text(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self::new(status)
            .with_header("content-type", "text/plain; charset=utf-8")
            .with_body(body)
    }

    /// Inserts a header, replacing existing values with the same name.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic unless a supplied conversion panics.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Replaces the response body.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic unless the supplied conversion panics.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Returns the first header value for a case-insensitive name.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }
}

/// Resource limits for response decoding and request encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http1ClientConfig {
    pub max_header_list_size: usize,
    /// Maximum decoded response body size.
    pub max_body_size: usize,
    /// Maximum encoded request body size, independent of response reassembly.
    pub max_request_body_size: usize,
}

impl Default for Http1ClientConfig {
    fn default() -> Self {
        Self {
            max_header_list_size: 16 * 1024,
            max_body_size: 16 * 1024 * 1024,
            max_request_body_size: usize::MAX,
        }
    }
}

/// Resource limits for request decoding and response encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http1ServerConfig {
    pub max_header_list_size: usize,
    pub max_body_size: usize,
}

impl Default for Http1ServerConfig {
    fn default() -> Self {
        Self {
            max_header_list_size: 16 * 1024,
            max_body_size: 16 * 1024 * 1024,
        }
    }
}

/// Connection disposition after a complete HTTP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http1KeepAlive {
    KeepAlive,
    Close,
    Upgrade,
}

/// HTTP/1 completion or protocol-upgrade notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1Event {
    MessageComplete { keep_alive: Http1KeepAlive },
    Upgraded { response: Response, trailing: Bytes },
}

#[cfg(test)]
mod integration_lifecycle_scenario_tests {
    use super::*;
    use crate::BytesMut;

    #[test]
    fn upgrade_encoder_rejects_implicit_body_framing_without_output() -> Result<()> {
        let request = Request::post("http://localhost/", "not a frame")?
            .with_header("connection", "upgrade")
            .with_header("upgrade", "websocket");
        let mut client = Http1ClientCodec::default();
        let mut output = BytesMut::new();
        output.extend_from_slice(b"prefix");
        assert!(matches!(
            client.encode_request(&request, &mut output),
            Err(ProtoError::Http1Protocol(_))
        ));
        assert_eq!(output.as_ref(), b"prefix");
        client.encode_request(&Request::get("http://localhost/")?, &mut output)?;
        assert!(output.starts_with(b"prefixGET / HTTP/1.1\r\n"));
        Ok(())
    }

    #[test]
    fn closing_request_allows_informational_then_final_response() -> Result<()> {
        let request = Request::get("http://localhost/")?.with_header("connection", "close");
        let mut client = Http1ClientCodec::default();
        let mut server = Http1ServerCodec::default();
        let mut wire = BytesMut::new();
        client.encode_request(&request, &mut wire)?;
        assert!(matches!(
            server.decode_request(&mut wire)?,
            Some((_, Http1KeepAlive::Close))
        ));
        server.encode_response(&Response::new(StatusCode::new(100)?), &mut wire)?;
        assert!(matches!(
            client.decode_response(&mut wire, Method::Get)?,
            Some((response, Http1KeepAlive::KeepAlive)) if response.status.as_u16() == 100
        ));
        server.encode_response(&Response::ok("complete"), &mut wire)?;
        assert!(matches!(
            client.decode_response(&mut wire, Method::Get)?,
            Some((response, Http1KeepAlive::Close)) if response.body.as_ref() == b"complete"
        ));
        assert!(client.decode_response(&mut wire, Method::Get).is_err());
        assert!(
            server
                .encode_response(&Response::ok("late"), &mut wire)
                .is_err()
        );
        assert!(wire.is_empty());
        Ok(())
    }

    #[test]
    fn reset_content_rejects_content_without_committing_input_or_output() -> Result<()> {
        let response = Response::new(StatusCode::new(205)?).with_body("forbidden");
        let mut output = BytesMut::new();
        output.extend_from_slice(b"prefix");
        assert!(matches!(
            Http1ServerCodec::default().encode_response(&response, &mut output),
            Err(ProtoError::Http1Protocol(_))
        ));
        assert_eq!(output.as_ref(), b"prefix");

        for framing in [
            "Content-Length: 1\r\n\r\nx",
            "Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        ] {
            let mut input = BytesMut::new();
            input.extend_from_slice(format!("HTTP/1.1 205 Reset Content\r\n{framing}").as_bytes());
            let before = input.clone();
            let mut client = Http1ClientCodec::default();
            assert!(matches!(
                client.decode_response(&mut input, Method::Get),
                Err(ProtoError::Http1Protocol(_))
            ));
            assert_eq!(input, before);
            input.clear();
            input.extend_from_slice(b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n");
            assert!(matches!(
                client.decode_response(&mut input, Method::Get)?,
                Some((response, Http1KeepAlive::KeepAlive)) if response.body.is_empty()
            ));
        }
        Ok(())
    }

    #[test]
    fn reset_content_zero_length_framing_preserves_the_following_response() -> Result<()> {
        for coding in [None, Some("chunked")] {
            let mut response = Response::new(StatusCode::new(205)?);
            if let Some(coding) = coding {
                response.headers.insert("transfer-encoding", coding);
            }
            let mut output = BytesMut::new();
            Http1ServerCodec::default().encode_response(&response, &mut output)?;
            output.extend_from_slice(b"following response");
            assert!(matches!(
                Http1ClientCodec::default().decode_response(&mut output, Method::Get)?,
                Some((response, Http1KeepAlive::KeepAlive)) if response.body.is_empty()
            ));
            assert_eq!(output.as_ref(), b"following response");
        }
        Ok(())
    }
}
