//! In-memory TLS 1.3 sessions. Transport reads and writes remain caller-owned.

use std::{
    io::{ErrorKind, Read, Write},
    sync::Arc,
};

use rustls::{
    ClientConnection, Connection, DigitallySignedStruct, RootCertStore, ServerConnection,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
    sign::{CertifiedKey, SingleCertAndKey},
};

use crate::{BytesMut, ProtoError, Result};

/// Application protocols supported by the TLS adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnProtocol {
    /// HTTP/1.1, advertised as `http/1.1`.
    Http11,
    /// HTTP/2, advertised as `h2`.
    Http2,
}

/// The local endpoint's handshake role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    /// Initiates the TLS handshake and verifies the server identity.
    Client,
    /// Accepts the handshake using its configured identity.
    Server,
}

/// Reusable TLS 1.3 client policy, using the ring cryptographic provider.
#[derive(Debug, Clone)]
pub struct TlsClientConfig {
    roots: Arc<RootCertStore>,
    alpn: Vec<Vec<u8>>,
    insecure: bool,
    client_auth: Option<Arc<CertifiedKey>>,
}

impl Default for TlsClientConfig {
    /// Uses public WebPKI trust anchors and prefers HTTP/2 over HTTP/1.1.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    fn default() -> Self {
        Self {
            roots: Arc::new(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            }),
            alpn: encode_alpn(&[AlpnProtocol::Http2, AlpnProtocol::Http11]),
            insecure: false,
            client_auth: None,
        }
    }
}

impl TlsClientConfig {
    /// Reports whether this policy permits HTTP/1.1 fallback.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn allows_http11(&self) -> bool {
        self.alpn.iter().any(|p| p.as_slice() == b"http/1.1")
    }

    /// Replaces the advertised ALPN protocols, retaining trust and client identity.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn with_alpn(mut self, alpn: &[AlpnProtocol]) -> Self {
        self.alpn = encode_alpn(alpn);
        self
    }

    /// Creates a test policy that skips certificate identity and trust checks.
    ///
    /// Handshake signatures are still verified. Do not use this policy with
    /// untrusted peers; it allows impersonation of any server name.
    ///
    /// # Errors
    /// This constructor currently always succeeds.
    ///
    /// # Panics
    /// Does not panic.
    pub fn insecure_client(alpn: &[AlpnProtocol]) -> Result<Self> {
        Ok(Self {
            roots: Arc::new(RootCertStore::empty()),
            alpn: encode_alpn(alpn),
            insecure: true,
            client_auth: None,
        })
    }

    /// Replaces public roots with the supplied DER-encoded trust anchors.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] if any trust anchor is invalid.
    ///
    /// # Panics
    /// Does not panic.
    pub fn with_root_certificates(cert_der: &[Vec<u8>], alpn: &[AlpnProtocol]) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in cert_der {
            roots
                .add(CertificateDer::from(cert.clone()))
                .map_err(tls_error)?;
        }
        Ok(Self {
            roots: Arc::new(roots),
            alpn: encode_alpn(alpn),
            insecure: false,
            client_auth: None,
        })
    }

    /// Replaces public roots with every certificate in a PEM trust bundle.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for malformed PEM, invalid certificates, or
    /// a bundle containing no certificates.
    ///
    /// # Panics
    /// Does not panic.
    pub fn with_pem_root_certificates(cert_pem: &[u8], alpn: &[AlpnProtocol]) -> Result<Self> {
        let certificates = CertificateDer::pem_slice_iter(cert_pem)
            .map(|item| item.map(|cert| cert.to_vec()).map_err(tls_error))
            .collect::<Result<Vec<_>>>()?;
        if certificates.is_empty() {
            return Err(ProtoError::Tls(
                "PEM bundle contains no certificates".to_owned(),
            ));
        }
        Self::with_root_certificates(&certificates, alpn)
    }

    /// Adds a DER client identity for servers requiring mutual authentication.
    ///
    /// The first certificate must match the supplied private key. Existing trust
    /// and ALPN policy are retained; peers still validate the identity's trust,
    /// validity period, and client-authentication usage during the handshake.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for an invalid identity or mismatched key.
    ///
    /// # Panics
    /// Does not panic.
    pub fn with_client_auth(
        mut self,
        cert_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
    ) -> Result<Self> {
        let identity = CertifiedKey::from_der(
            cert_chain_der
                .into_iter()
                .map(CertificateDer::from)
                .collect(),
            PrivateKeyDer::try_from(private_key_der).map_err(tls_error)?,
            &rustls::crypto::ring::default_provider(),
        )
        .map_err(tls_error)?;
        self.client_auth = Some(Arc::new(identity));
        Ok(self)
    }
}

/// Reusable TLS 1.3 server identity and ALPN preference order.
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    inner: Arc<rustls::ServerConfig>,
}

impl TlsServerConfig {
    /// Loads a DER certificate chain and a PKCS#1, PKCS#8, or SEC1 private key.
    ///
    /// The first certificate must identify the server and match the key.
    /// Client certificates are not requested.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for an invalid identity or cryptographic policy.
    ///
    /// # Panics
    /// Does not panic.
    pub fn from_der(
        cert_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        alpn: &[AlpnProtocol],
    ) -> Result<Self> {
        Self::from_der_with_verifier(
            cert_chain_der,
            private_key_der,
            alpn,
            WebPkiClientVerifier::no_client_auth(),
        )
    }

    /// Loads a server identity and requires a client certificate trusted by the
    /// supplied DER authorities. Unauthenticated clients are rejected.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for an invalid server identity, invalid or
    /// empty client authorities, or unsupported cryptographic policy.
    ///
    /// # Panics
    /// Does not panic.
    pub fn from_der_with_client_auth(
        cert_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        client_ca_der: &[Vec<u8>],
        alpn: &[AlpnProtocol],
    ) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in client_ca_der {
            roots
                .add(CertificateDer::from(cert.clone()))
                .map_err(tls_error)?;
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(tls_error)?;
        Self::from_der_with_verifier(cert_chain_der, private_key_der, alpn, verifier)
    }

    fn from_der_with_verifier(
        cert_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        alpn: &[AlpnProtocol],
        verifier: Arc<dyn ClientCertVerifier>,
    ) -> Result<Self> {
        let chain = cert_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = PrivateKeyDer::try_from(private_key_der).map_err(tls_error)?;
        let mut inner = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(tls_error)?;
        inner.alpn_protocols = encode_alpn(alpn);
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Generates a fresh localhost identity and returns its DER trust anchor.
    ///
    /// The certificate also covers the loopback IP addresses `127.0.0.1` and
    /// `::1`. Key generation uses the system random source.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] if identity generation or loading fails.
    ///
    /// # Panics
    /// Does not panic.
    pub fn self_signed_for_localhost(alpn: &[AlpnProtocol]) -> Result<(Self, Vec<u8>)> {
        let identity = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])
        .map_err(tls_error)?;
        let cert_der = identity.cert.der().to_vec();
        let config = Self::from_der(
            vec![cert_der.clone()],
            identity.key_pair.serialize_der(),
            alpn,
        )?;
        Ok((config, cert_der))
    }
}

/// TLS record processing with no socket ownership or blocking I/O.
///
/// `feed_ciphertext` owns a copy of all supplied bytes. Coalesced records that
/// cannot yet be processed remain queued until plaintext is drained or handshake
/// output is taken. Drain both directions while completing a handshake.
pub struct TlsSession {
    connection: Connection,
    pending_ciphertext: BytesMut,
    plaintext_available: usize,
    peer_closed: bool,
    local_closed: bool,
    failure: Option<String>,
}

impl TlsSession {
    /// Creates a client session and queues its initial handshake flight.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for an invalid name or cryptographic policy.
    ///
    /// # Panics
    /// Does not panic.
    pub fn new_client(config: &TlsClientConfig, server_name: &str) -> Result<Self> {
        let name = ServerName::try_from(server_name.to_owned()).map_err(tls_error)?;
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?;
        let builder = if config.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TestVerifier))
        } else {
            builder.with_root_certificates(Arc::clone(&config.roots))
        };
        let mut inner = match &config.client_auth {
            Some(identity) => builder
                .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(identity)))),
            None => builder.with_no_client_auth(),
        };
        inner.alpn_protocols = config.alpn.clone();
        let connection = ClientConnection::new(Arc::new(inner), name).map_err(tls_error)?;
        Ok(Self::from_connection(Connection::Client(connection)))
    }

    /// Creates a server session awaiting the client's first handshake flight.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] if rustls cannot create the session.
    ///
    /// # Panics
    /// Does not panic.
    pub fn new_server(config: &TlsServerConfig) -> Result<Self> {
        let connection = ServerConnection::new(Arc::clone(&config.inner)).map_err(tls_error)?;
        Ok(Self::from_connection(Connection::Server(connection)))
    }

    fn from_connection(connection: Connection) -> Self {
        Self {
            connection,
            pending_ciphertext: BytesMut::new(),
            plaintext_available: 0,
            peer_closed: false,
            local_closed: false,
            failure: None,
        }
    }

    /// Returns the local endpoint's role.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn role(&self) -> TlsRole {
        match &self.connection {
            Connection::Client(_) => TlsRole::Client,
            Connection::Server(_) => TlsRole::Server,
        }
    }

    /// Returns whether handshake processing is still in progress.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn is_handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }

    /// Returns whether the transport should supply more ciphertext.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn wants_read(&self) -> bool {
        self.failure.is_none() && self.connection.wants_read()
    }

    /// Returns whether encrypted output needs to be drained.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn wants_write(&self) -> bool {
        self.connection.wants_write()
    }

    /// Returns the negotiated application protocol, if available.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn alpn_protocol(&self) -> Option<AlpnProtocol> {
        match self.connection.alpn_protocol() {
            Some(b"h2") => Some(AlpnProtocol::Http2),
            Some(b"http/1.1") => Some(AlpnProtocol::Http11),
            _ => None,
        }
    }

    /// Accepts all supplied ciphertext and returns currently readable plaintext bytes.
    ///
    /// This return value is not the number of input bytes consumed. Empty input
    /// does not indicate transport EOF. Record fragments are retained internally.
    ///
    /// Data received after the peer's close notification is discarded, including
    /// bytes coalesced with that notification. Previously received plaintext
    /// remains readable and the local sending direction remains open.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for invalid records, handshake failures, or a
    /// previous fatal error.
    ///
    /// # Panics
    /// Does not panic.
    pub fn feed_ciphertext(&mut self, ciphertext: &[u8]) -> Result<usize> {
        self.check_failure()?;
        if self.peer_closed {
            return Ok(self.plaintext_available);
        }
        self.pending_ciphertext.extend_from_slice(ciphertext);
        self.process_pending()?;
        Ok(self.plaintext_available)
    }

    /// Appends all currently obtainable plaintext to `out` using a fixed scratch buffer.
    ///
    /// Also processes queued coalesced records as their plaintext is drained.
    /// Returns zero when no plaintext is available, including after clean closure.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for record or plaintext read failures. Output
    /// appended before an error remains in `out`.
    ///
    /// # Panics
    /// Does not panic.
    pub fn read_plaintext(&mut self, out: &mut BytesMut) -> Result<usize> {
        self.check_failure()?;
        let before = out.len();
        let mut scratch = [0_u8; 16_384];
        loop {
            self.process_pending()?;
            match self.connection.reader().read(&mut scratch) {
                Ok(0) => break,
                Ok(count) => {
                    out.extend_from_slice(&scratch[..count]);
                    self.plaintext_available = self.plaintext_available.saturating_sub(count);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return self.fail(error.to_string()),
            }
        }
        Ok(out.len() - before)
    }

    /// Queues plaintext for encryption and returns the accepted byte count.
    ///
    /// Writes may be partial due to rustls buffer limits, including during the
    /// handshake. Drain ciphertext and retry the unaccepted suffix.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] for a previous fatal error, a closed sending
    /// direction, or a plaintext write failure. Receiving the peer's close
    /// notification leaves the local sending direction open.
    ///
    /// # Panics
    /// Does not panic.
    pub fn write_plaintext(&mut self, plaintext: &[u8]) -> Result<usize> {
        self.check_failure()?;
        if self.local_closed {
            return Err(ProtoError::Tls(
                "plaintext write after TLS closure".to_owned(),
            ));
        }
        self.connection.writer().write(plaintext).map_err(tls_error)
    }

    /// Appends queued handshake, application, and alert ciphertext to `out`.
    ///
    /// A fatal protocol error may leave an alert available for transmission.
    ///
    /// # Errors
    /// Returns [`ProtoError::Tls`] if output extraction or queued record
    /// processing fails. Bytes appended before an error remain in `out`.
    ///
    /// # Panics
    /// Does not panic.
    pub fn take_ciphertext(&mut self, out: &mut BytesMut) -> Result<usize> {
        let before = out.len();
        loop {
            while self.connection.wants_write() {
                let written = self
                    .connection
                    .write_tls(&mut BufferWriter(out))
                    .map_err(tls_error)?;
                if written == 0 {
                    return Err(ProtoError::Tls("TLS output made no progress".to_owned()));
                }
            }
            if self.failure.is_some() || self.pending_ciphertext.is_empty() {
                break;
            }
            self.process_pending()?;
            if !self.connection.wants_write() {
                break;
            }
        }
        Ok(out.len() - before)
    }

    /// Closes the sending direction and queues one TLS close notification.
    ///
    /// Repeated calls are harmless. During the handshake, closure is deferred
    /// until previously accepted plaintext can be encrypted before the alert.
    /// Further plaintext writes fail immediately. Drain ciphertext to transmit
    /// the handshake and alert.
    ///
    /// # Errors
    /// This operation is infallible.
    ///
    /// # Panics
    /// Does not panic.
    pub fn send_close_notify(&mut self) {
        self.local_closed = true;
        self.flush_close_notify();
    }

    fn check_failure(&self) -> Result<()> {
        match &self.failure {
            Some(reason) => Err(ProtoError::Tls(reason.clone())),
            None => Ok(()),
        }
    }

    fn fail<T>(&mut self, reason: String) -> Result<T> {
        self.failure = Some(reason.clone());
        Err(ProtoError::Tls(reason))
    }

    fn flush_close_notify(&mut self) {
        if self.local_closed && !self.connection.is_handshaking() {
            self.connection.send_close_notify();
        }
    }

    fn process_pending(&mut self) -> Result<()> {
        self.check_failure()?;
        while !self.pending_ciphertext.is_empty() && self.connection.wants_read() {
            let mut input = self.pending_ciphertext.as_slice();
            let count = match self.connection.read_tls(&mut input) {
                Ok(count) => count,
                Err(error) => return self.fail(error.to_string()),
            };
            if count == 0 {
                return self.fail("TLS input made no progress".to_owned());
            }
            self.pending_ciphertext.advance(count);
            let state = match self.connection.process_new_packets() {
                Ok(state) => state,
                Err(error) => return self.fail(error.to_string()),
            };
            self.plaintext_available = state.plaintext_bytes_to_read();
            self.peer_closed = state.peer_has_closed();
            self.flush_close_notify();
        }
        if self.peer_closed {
            self.pending_ciphertext.clear();
        }
        Ok(())
    }
}

struct BufferWriter<'a>(&'a mut BytesMut);

impl Write for BufferWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_alpn(protocols: &[AlpnProtocol]) -> Vec<Vec<u8>> {
    protocols
        .iter()
        .map(|protocol| match protocol {
            AlpnProtocol::Http11 => b"http/1.1".to_vec(),
            AlpnProtocol::Http2 => b"h2".to_vec(),
        })
        .collect()
}

fn tls_error(error: impl std::fmt::Display) -> ProtoError {
    ProtoError::Tls(error.to_string())
}

#[derive(Debug)]
struct TestVerifier;

impl ServerCertVerifier for TestVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is disabled".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
