//! Reusable TLS trust, identity and ALPN policy.
use std::sync::Arc;

use super::{
    AlpnProtocol, ProtoError, Result,
    certificate::{Secret, localhost},
    context::{Context, Roots, error, pem_roots},
};

/// Reusable AWS-LC TLS 1.3 client trust and identity policy.
#[derive(Debug, Clone)]
pub struct TlsClientConfig {
    pub(super) alpn: Vec<Vec<u8>>,
    pub(super) insecure: bool,
    context: std::result::Result<Arc<Context>, Arc<str>>,
}
impl Default for TlsClientConfig {
    /// Loads host CA paths and prefers HTTP/2, then HTTP/1.1.
    fn default() -> Self {
        let roots = Roots::Native;
        let context = Context::client(&roots, false)
            .map(Arc::new)
            .map_err(|error| Arc::<str>::from(error.to_string()));
        Self {
            alpn: encode_alpn(&[AlpnProtocol::Http2, AlpnProtocol::Http11]),
            insecure: false,
            context,
        }
    }
}
impl TlsClientConfig {
    /// Reports whether HTTP/1.1 fallback is permitted.
    pub fn allows_http11(&self) -> bool {
        self.alpn.iter().any(|p| p == b"http/1.1")
    }
    /// Replaces ALPN preferences, retaining trust and client identity.
    #[must_use]
    pub fn with_alpn(mut self, alpn: &[AlpnProtocol]) -> Self {
        self.alpn = encode_alpn(alpn);
        self
    }
    /// Bypasses X.509 trust and hostname checks while verifying handshake signatures.
    /// Use only with controlled test peers: this permits impersonation.
    /// # Errors
    /// Returns a TLS error if AWS-LC cannot construct the context.
    pub fn insecure_client(alpn: &[AlpnProtocol]) -> Result<Self> {
        Self::new(Roots::Empty, alpn, true)
    }
    /// Replaces host roots with DER trust anchors.
    /// # Errors
    /// Returns a TLS error for invalid certificates or context allocation failure.
    pub fn with_root_certificates(cert_der: &[Vec<u8>], alpn: &[AlpnProtocol]) -> Result<Self> {
        Self::new(Roots::Der(Arc::new(cert_der.to_vec())), alpn, false)
    }
    /// Loads every certificate in a PEM bundle as a trust anchor.
    /// # Errors
    /// Rejects empty, malformed or invalid certificate bundles.
    pub fn with_pem_root_certificates(cert_pem: &[u8], alpn: &[AlpnProtocol]) -> Result<Self> {
        Self::with_root_certificates(&pem_roots(cert_pem)?, alpn)
    }
    /// Adds a DER certificate chain and matching PKCS#1, PKCS#8 or SEC1 key.
    /// # Errors
    /// Returns a TLS error for malformed identities or a mismatched private key.
    pub fn with_client_auth(
        mut self,
        cert_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
    ) -> Result<Self> {
        let key = Secret(private_key_der);
        let mut context = Context::copy_client(self.context()?.as_ref(), self.insecure)?;
        context.identity(&cert_chain_der, &key.0)?;
        self.context = Ok(Arc::new(context));
        Ok(self)
    }
    fn new(roots: Roots, alpn: &[AlpnProtocol], insecure: bool) -> Result<Self> {
        let context = Ok(Arc::new(Context::client(&roots, insecure)?));
        Ok(Self {
            alpn: encode_alpn(alpn),
            insecure,
            context,
        })
    }
    pub(super) fn context(&self) -> Result<Arc<Context>> {
        self.context
            .as_ref()
            .map(Arc::clone)
            .map_err(|reason| ProtoError::Tls(reason.to_string()))
    }
}

/// Reusable TLS 1.3 server identity and ALPN preference order.
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    pub(super) inner: Arc<Context>,
}
impl TlsServerConfig {
    /// Loads a DER identity without requesting client authentication.
    /// # Errors
    /// Rejects malformed certificate chains, invalid keys and key mismatches.
    pub fn from_der(
        cert_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        alpn: &[AlpnProtocol],
    ) -> Result<Self> {
        Self::identity(cert_chain_der, Secret(private_key_der), alpn, None)
    }
    /// Requires a client certificate trusted by the supplied DER authorities.
    /// # Errors
    /// Rejects an invalid server identity, empty authorities or malformed roots.
    pub fn from_der_with_client_auth(
        cert_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        client_ca_der: &[Vec<u8>],
        alpn: &[AlpnProtocol],
    ) -> Result<Self> {
        let private_key_der = Secret(private_key_der);
        if client_ca_der.is_empty() {
            return Err(error("empty client trust anchors"));
        }
        Self::identity(
            cert_chain_der,
            private_key_der,
            alpn,
            Some(Roots::Der(Arc::new(client_ca_der.to_vec()))),
        )
    }
    fn identity(
        chain: Vec<Vec<u8>>,
        key: Secret,
        alpn: &[AlpnProtocol],
        roots: Option<Roots>,
    ) -> Result<Self> {
        let mut context = Context::new(encode_alpn(alpn))?;
        context.identity(&chain, &key.0)?;
        context.server(roots.as_ref())?;
        Ok(Self {
            inner: Arc::new(context),
        })
    }
    /// Generates a fresh P-256 identity for localhost and both loopback IPs.
    /// Returns the DER certificate to install as a test trust anchor.
    /// # Errors
    /// Returns a TLS error if key generation, signing or identity loading fails.
    pub fn self_signed_for_localhost(alpn: &[AlpnProtocol]) -> Result<(Self, Vec<u8>)> {
        let (cert, key) = localhost()?;
        let mut context = Context::new(encode_alpn(alpn))?;
        context.identity(std::slice::from_ref(&cert), &key.0)?;
        context.server(None)?;
        Ok((
            Self {
                inner: Arc::new(context),
            },
            cert,
        ))
    }
}
pub(super) fn encode_alpn(protocols: &[AlpnProtocol]) -> Vec<Vec<u8>> {
    protocols
        .iter()
        .map(|p| match p {
            AlpnProtocol::Http11 => b"http/1.1".to_vec(),
            AlpnProtocol::Http2 => b"h2".to_vec(),
        })
        .collect()
}
