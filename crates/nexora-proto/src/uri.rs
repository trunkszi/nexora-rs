//! Absolute HTTP and WebSocket URIs and relative redirect resolution.

use std::net::Ipv6Addr;

use crate::error::{ProtoError, Result};

/// Supported application protocol schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Scheme {
    /// Cleartext HTTP.
    #[default]
    Http,
    /// HTTP protected by TLS.
    Https,
    /// Cleartext WebSocket.
    WebSocket,
    /// WebSocket protected by TLS.
    WebSocketSecure,
}

impl Scheme {
    /// Returns the lowercase scheme name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::WebSocket => "ws",
            Self::WebSocketSecure => "wss",
        }
    }

    /// Returns the default TCP port.
    pub fn default_port(self) -> u16 {
        if self.is_tls() { 443 } else { 80 }
    }

    /// Reports whether transport encryption is required.
    pub fn is_tls(self) -> bool {
        matches!(self, Self::Https | Self::WebSocketSecure)
    }

    /// Reports whether the scheme selects WebSocket.
    pub fn is_websocket(self) -> bool {
        matches!(self, Self::WebSocket | Self::WebSocketSecure)
    }

    /// Parses an ASCII case-insensitive scheme name.
    ///
    /// # Errors
    /// Returns an invalid-URI error for an unsupported scheme.
    pub fn parse(s: &str) -> Result<Self> {
        if s.eq_ignore_ascii_case("http") {
            Ok(Self::Http)
        } else if s.eq_ignore_ascii_case("https") {
            Ok(Self::Https)
        } else if s.eq_ignore_ascii_case("ws") {
            Ok(Self::WebSocket)
        } else if s.eq_ignore_ascii_case("wss") {
            Ok(Self::WebSocketSecure)
        } else {
            Err(invalid("unsupported scheme"))
        }
    }
}

/// An absolute URI with a nonempty authority and an origin-form request target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Uri {
    scheme: Scheme,
    host: String,
    port: u16,
    explicit_port: bool,
    path_and_query: String,
    serialized: String,
}

impl Uri {
    /// Parses an absolute URI, omitting its fragment from the request target.
    ///
    /// # Errors
    /// Returns an invalid-URI error for unsupported schemes, malformed authorities,
    /// user information, invalid ports, invalid component characters or escapes.
    pub fn parse(raw: &str) -> Result<Self> {
        validate_reference(raw)?;
        let raw = raw.split('#').next().unwrap_or_default();
        let (scheme, remainder) = raw
            .split_once("://")
            .ok_or_else(|| invalid("absolute URI requires a scheme and authority"))?;
        let scheme = Scheme::parse(scheme)?;
        let boundary = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority = &remainder[..boundary];
        let target = &remainder[boundary..];
        let (host, port, explicit_port) = parse_authority(authority, scheme)?;
        validate_target(target)?;
        let path_and_query = if target.is_empty() {
            "/".to_owned()
        } else if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_owned()
        };
        let mut uri = Self {
            scheme,
            host,
            port,
            explicit_port,
            path_and_query,
            serialized: String::new(),
        };
        uri.serialized = format!(
            "{}://{}{}",
            uri.scheme.as_str(),
            uri.authority(),
            uri.path_and_query
        );
        Ok(uri)
    }

    /// Returns the application scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Returns the lowercase host without IPv6 brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the explicit or scheme-default TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the request path and optional query, excluding any fragment.
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    /// Returns the request path without a query.
    pub fn path(&self) -> &str {
        self.path_and_query
            .split_once('?')
            .map_or(&self.path_and_query, |(path, _)| path)
    }

    /// Returns the query without its leading question mark.
    pub fn query(&self) -> Option<&str> {
        self.path_and_query.split_once('?').map(|(_, query)| query)
    }

    /// Returns the authority, retaining explicit ports and IPv6 brackets.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.explicit_port {
            format!("{host}:{}", self.port)
        } else {
            host
        }
    }

    /// Returns the normalized absolute URI without a fragment.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Resolves an absolute or relative Location value against this URI.
    ///
    /// # Errors
    /// Returns an invalid-URI error for invalid references or authorities, including
    /// unsupported schemes. Literal dot segments are removed from redirect paths.
    pub fn resolve_redirect(&self, location: &str) -> Result<Self> {
        validate_reference(location)?;
        let location = location.split('#').next().unwrap_or_default();
        let first_segment = location.split(['/', '?']).next().unwrap_or_default();
        if first_segment.contains(':') {
            let absolute = Self::parse(location)?;
            return absolute.with_normalized_path();
        }
        if location.starts_with("//") {
            let absolute = Self::parse(&format!("{}:{location}", self.scheme.as_str()))?;
            return absolute.with_normalized_path();
        }
        if location.is_empty() {
            return Ok(self.clone());
        }
        if location.starts_with('?') {
            return Self::parse(&format!(
                "{}://{}{}{location}",
                self.scheme.as_str(),
                self.authority(),
                self.path()
            ));
        }
        let target = if location.starts_with('/') {
            location.to_owned()
        } else {
            let directory = self
                .path()
                .rfind('/')
                .map_or("/", |end| &self.path()[..=end]);
            format!("{directory}{location}")
        };
        validate_target(&target)?;
        let target = normalize_target(&target);
        Self::parse(&format!(
            "{}://{}{target}",
            self.scheme.as_str(),
            self.authority()
        ))
    }

    fn with_normalized_path(self) -> Result<Self> {
        Self::parse(&format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.authority(),
            normalize_target(&self.path_and_query)
        ))
    }
}

fn invalid(reason: &str) -> ProtoError {
    ProtoError::InvalidUri(reason.to_owned())
}

fn validate_reference(raw: &str) -> Result<()> {
    let bytes = raw.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if !byte.is_ascii_alphanumeric() && !b"-._~!$&'()*+,;=:/?@[]#%".contains(byte) {
            return Err(invalid("invalid URI character"));
        }
        if *byte == b'%'
            && (!bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit))
        {
            return Err(invalid("invalid percent escape"));
        }
    }
    if let Some((_, fragment)) = raw.split_once('#') {
        validate_component(fragment, true)?;
    }
    Ok(())
}

fn validate_component(component: &str, allow_question_mark: bool) -> Result<()> {
    if component.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=:@%/".contains(&byte)
            || (allow_question_mark && byte == b'?')
    }) {
        Ok(())
    } else {
        Err(invalid("invalid path, query or fragment character"))
    }
}

fn validate_target(target: &str) -> Result<()> {
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    validate_component(path, false)?;
    if let Some(query) = query {
        validate_component(query, true)?;
    }
    Ok(())
}

fn parse_authority(authority: &str, scheme: Scheme) -> Result<(String, u16, bool)> {
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid("authority is empty or contains user information"));
    }
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, suffix) = ipv6
            .split_once(']')
            .ok_or_else(|| invalid("IPv6 address is missing a closing bracket"))?;
        host.parse::<Ipv6Addr>()
            .map_err(|_| invalid("invalid IPv6 address"))?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| invalid("invalid authority suffix"))?,
            )
        };
        (host, port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=%".contains(&byte))
        {
            return Err(invalid("invalid host name or unbracketed IPv6 address"));
        }
        (host, port)
    };
    let explicit_port = port.is_some();
    let port = match port {
        Some(port) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| invalid("port is outside 1..=65535"))?;
            if port == 0 {
                return Err(invalid("port is outside 1..=65535"));
            }
            port
        }
        Some(_) => return Err(invalid("port must contain decimal digits")),
        None => scheme.default_port(),
    };
    Ok((host.to_ascii_lowercase(), port, explicit_port))
}

fn normalize_target(target: &str) -> String {
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let mut segments = Vec::new();
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        match part {
            "." => {
                if parts.peek().is_none() {
                    segments.push("");
                }
            }
            ".." => {
                if segments.len() > 1 {
                    segments.pop();
                }
                if parts.peek().is_none() {
                    segments.push("");
                }
            }
            _ => segments.push(part),
        }
    }
    let mut normalized = segments.join("/");
    if normalized.is_empty() {
        normalized.push('/');
    }
    if let Some(query) = query {
        normalized.push('?');
        normalized.push_str(query);
    }
    normalized
}
