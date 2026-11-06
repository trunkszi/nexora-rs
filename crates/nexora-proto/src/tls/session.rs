//! Exclusive SSL and memory BIO ownership with caller-controlled progress.
use std::{
    ffi::CString,
    net::IpAddr,
    ptr::{self, NonNull},
    sync::Arc,
};

use aws_lc_sys as ffi;

use super::{
    AlpnProtocol, BytesMut, ProtoError, Result, TlsClientConfig, TlsRole, TlsServerConfig,
    context::{Context, error},
    state::TlsStateWord,
};

const RECORD_LIMIT: usize = 18_432;
const WRITE_LIMIT: usize = 16_384;
const QUEUED_LIMIT: usize = 65_536;

/// TLS 1.3 records over memory buffers without sockets or blocking I/O.
/// All supplied ciphertext is retained until processed. Drain both directions
/// during handshaking and retry the unaccepted suffix of partial writes.
pub struct TlsSession {
    ssl: NonNull<ffi::SSL>,
    _context: Arc<Context>,
    role: TlsRole,
    pending_ciphertext: BytesMut,
    pending_plaintext: BytesMut,
    plaintext: BytesMut,
    state: TlsStateWord,
    failure: Option<String>,
}
impl Drop for TlsSession {
    fn drop(&mut self) {
        // SAFETY: this session exclusively owns SSL, which owns both BIOs. The
        // retained context and its callback policy are dropped after SSL_free.
        unsafe { ffi::SSL_free(self.ssl.as_ptr()) };
    }
}
impl TlsSession {
    /// Creates a client and queues its ClientHello.
    /// # Errors
    /// Rejects invalid names, unavailable trust paths and TLS initialization errors.
    pub fn new_client(config: &TlsClientConfig, server_name: &str) -> Result<Self> {
        let ip = server_name.parse::<IpAddr>().is_ok();
        let dns = server_name.strip_suffix('.').unwrap_or(server_name);
        if !ip
            && (dns.is_empty()
                || dns.len() > 253
                || !dns.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }))
        {
            return Err(error("invalid TLS server name"));
        }
        let name = CString::new(server_name).map_err(|_| error("invalid TLS server name"))?;
        let mut session = Self::new(config.context()?, TlsRole::Client)?;
        let mut alpn = Vec::new();
        for protocol in &config.alpn {
            alpn.push(protocol.len() as u8);
            alpn.extend_from_slice(protocol);
        }
        // SAFETY: SSL is exclusive; the name and ALPN are copied by AWS-LC.
        unsafe {
            let ssl = session.ssl.as_ptr();
            if ffi::SSL_set_alpn_protos(ssl, alpn.as_ptr(), alpn.len()) != 0 {
                return Err(error("configure client ALPN"));
            }
            let params = ffi::SSL_get0_param(ssl);
            ffi::X509_VERIFY_PARAM_set_hostflags(
                params,
                ffi::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT as _,
            );
            let verified = if ip {
                ffi::X509_VERIFY_PARAM_set1_ip_asc(params, name.as_ptr())
            } else {
                if ffi::SSL_set_tlsext_host_name(ssl, name.as_ptr()) != 1 {
                    return Err(error("set SNI"));
                }
                ffi::X509_VERIFY_PARAM_set1_host(params, name.as_ptr(), 0)
            };
            if verified != 1 {
                return Err(error("configure peer identity"));
            }
        }
        session.drive()?;
        Ok(session)
    }
    /// Creates a server awaiting a ClientHello.
    /// # Errors
    /// Returns a TLS error if SSL or BIO allocation fails.
    pub fn new_server(config: &TlsServerConfig) -> Result<Self> {
        Self::new(Arc::clone(&config.inner), TlsRole::Server)
    }
    fn new(context: Arc<Context>, role: TlsRole) -> Result<Self> {
        // SAFETY: the context is live; SSL_new retains its own context reference.
        let ssl = NonNull::new(unsafe { ffi::SSL_new(context.raw.as_ptr()) })
            .ok_or_else(|| error("allocate TLS session"))?;
        let session = Self {
            ssl,
            _context: context,
            role,
            pending_ciphertext: BytesMut::new(),
            pending_plaintext: BytesMut::new(),
            plaintext: BytesMut::new(),
            state: TlsStateWord::default(),
            failure: None,
        };
        // SAFETY: SSL is exclusively owned. Both BIO references transfer together
        // on success; a failed allocation releases any BIO that did succeed.
        unsafe {
            let input = ffi::BIO_new(ffi::BIO_s_mem());
            let output = ffi::BIO_new(ffi::BIO_s_mem());
            if input.is_null() || output.is_null() {
                ffi::BIO_free(input);
                ffi::BIO_free(output);
                return Err(error("allocate TLS BIO"));
            }
            ffi::SSL_set_bio(ssl.as_ptr(), input, output);
            if role == TlsRole::Client {
                ffi::SSL_set_connect_state(ssl.as_ptr());
            } else {
                ffi::SSL_set_accept_state(ssl.as_ptr());
            }
        }
        Ok(session)
    }
    /// Returns the local endpoint's role.
    #[uarch::hot_inline]
    pub fn role(&self) -> TlsRole {
        self.role
    }
    /// Reports whether handshake processing is still in progress.
    #[inline]
    pub fn is_handshaking(&self) -> bool {
        // SAFETY: SSL remains live for the complete borrow.
        unsafe { ffi::SSL_is_init_finished(self.ssl.as_ptr()) != 1 }
    }
    /// Reports whether the receiving direction accepts more ciphertext.
    #[inline]
    pub fn wants_read(&self) -> bool {
        self.failure.is_none() && !self.state.peer_closed()
    }
    /// Reports whether encrypted output is waiting to be drained.
    #[inline]
    pub fn wants_write(&self) -> bool {
        // SAFETY: the output BIO is owned by this live SSL.
        unsafe { ffi::BIO_ctrl_pending(ffi::SSL_get_wbio(self.ssl.as_ptr())) != 0 }
    }
    /// Returns the negotiated application protocol, if any.
    #[inline]
    pub fn alpn_protocol(&self) -> Option<AlpnProtocol> {
        let mut bytes = ptr::null();
        let mut len = 0;
        // SAFETY: SSL returns a borrowed ALPN value that lives through this borrow.
        unsafe {
            ffi::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut bytes, &mut len);
            if len == 0 {
                return None;
            }
            match std::slice::from_raw_parts(bytes, len as usize) {
                b"h2" => Some(AlpnProtocol::Http2),
                b"http/1.1" => Some(AlpnProtocol::Http11),
                _ => None,
            }
        }
    }
    /// Accepts all ciphertext and returns currently buffered plaintext bytes.
    /// Empty input does not indicate EOF. Bytes after a peer close are discarded.
    /// # Errors
    /// Returns a TLS error for invalid records, failed authentication or a prior fatal error.
    pub fn feed_ciphertext(&mut self, ciphertext: &[u8]) -> Result<usize> {
        self.check_failure()?;
        if self.state.peer_closed() {
            return Ok(self.plaintext.len());
        }
        self.pending_ciphertext.extend_from_slice(ciphertext);
        self.process_pending()?;
        Ok(self.plaintext.len())
    }
    /// Appends all obtainable plaintext, preserving any existing output prefix.
    /// # Errors
    /// Returns a TLS error for a previous fatal error or failed record processing.
    #[inline]
    pub fn read_plaintext(&mut self, out: &mut BytesMut) -> Result<usize> {
        self.check_failure()?;
        self.process_pending()?;
        let count = self.plaintext.len();
        out.extend_from_slice(&self.plaintext);
        self.plaintext.clear();
        Ok(count)
    }
    /// Accepts plaintext for encryption, possibly as a partial write.
    /// At most 64 KiB of plaintext/ciphertext is queued, plus final record overhead. Drain
    /// ciphertext and retry the unaccepted suffix. Peer closure leaves the local direction open.
    /// # Errors
    /// Returns a TLS error for a closed sending direction or fatal TLS failure.
    #[inline]
    pub fn write_plaintext(&mut self, plaintext: &[u8]) -> Result<usize> {
        self.check_failure()?;
        if self.state.local_closed() {
            return Err(error("plaintext write after TLS closure"));
        }
        // Bound both encrypted output and plaintext accepted before the handshake.
        // Record overhead can exceed the budget only for the last accepted record.
        let buffered = self
            .pending_plaintext
            .len()
            .saturating_add(self.ciphertext_len());
        let accepted = plaintext.len().min(QUEUED_LIMIT.saturating_sub(buffered));
        self.pending_plaintext
            .extend_from_slice(&plaintext[..accepted]);
        if !self.is_handshaking() {
            self.flush_plaintext()?;
        }
        Ok(accepted)
    }
    /// Appends queued handshake, application and alert ciphertext.
    /// A fatal protocol error may still leave an alert available to transmit.
    /// # Errors
    /// Returns a TLS error if output extraction fails.
    pub fn take_ciphertext(&mut self, out: &mut BytesMut) -> Result<usize> {
        let before = out.len();
        let mut scratch = [0; WRITE_LIMIT];
        while self.wants_write() {
            // SAFETY: the output BIO is live and scratch has the supplied capacity.
            let count = unsafe {
                ffi::BIO_read(
                    ffi::SSL_get_wbio(self.ssl.as_ptr()),
                    scratch.as_mut_ptr().cast(),
                    scratch.len() as i32,
                )
            };
            if count <= 0 {
                return self.fail(error("TLS output made no progress"));
            }
            out.extend_from_slice(&scratch[..count as usize]);
        }
        Ok(out.len() - before)
    }
    /// Closes the sending direction and queues one close notification.
    /// Repeated calls are harmless. Handshaking and accepted plaintext finish
    /// before a deferred notification is sent; further writes fail immediately.
    pub fn send_close_notify(&mut self) {
        self.state.set_local_closed(true);
        if self.failure.is_none()
            && let Err(error) = self.flush_close_notify()
        {
            self.failure = Some(error.to_string());
        }
    }
    fn check_failure(&self) -> Result<()> {
        match &self.failure {
            Some(reason) => Err(ProtoError::Tls(reason.clone())),
            None => Ok(()),
        }
    }
    #[uarch::cold_sink]
    fn fail<T>(&mut self, failure: ProtoError) -> Result<T> {
        let reason = match failure {
            ProtoError::Tls(reason) => reason,
            other => other.to_string(),
        };
        self.failure = Some(reason.clone());
        Err(ProtoError::Tls(reason))
    }
    fn process_pending(&mut self) -> Result<()> {
        self.check_failure()?;
        while self.pending_ciphertext.len() >= 5 {
            let count = 5 + usize::from(u16::from_be_bytes([
                self.pending_ciphertext[3],
                self.pending_ciphertext[4],
            ]));
            if count > RECORD_LIMIT + 5 {
                return self.fail(error("oversized TLS record"));
            }
            if self.pending_ciphertext.len() < count {
                break;
            }
            // SAFETY: memory BIO copies this complete, bounded live record.
            let written = unsafe {
                ffi::BIO_write(
                    ffi::SSL_get_rbio(self.ssl.as_ptr()),
                    self.pending_ciphertext.as_ptr().cast(),
                    count as i32,
                )
            };
            if written != count as i32 {
                return self.fail(error("TLS input made no progress"));
            }
            self.pending_ciphertext.advance(count);
            self.drive()?;
            if self.state.peer_closed() {
                self.pending_ciphertext.clear();
                break;
            }
        }
        Ok(())
    }
    fn drive(&mut self) -> Result<()> {
        if self.is_handshaking() {
            // SAFETY: SSL is exclusive and uses memory BIOs. SSL_get_error must
            // immediately follow the operation with a clear thread-local queue.
            let (result, status) = unsafe {
                ffi::ERR_clear_error();
                let result = ffi::SSL_do_handshake(self.ssl.as_ptr());
                (result, ffi::SSL_get_error(self.ssl.as_ptr(), result))
            };
            if result != 1 && !would_block(status) {
                return self.fail(error("TLS handshake failed"));
            }
        }
        if self.is_handshaking() {
            return Ok(());
        }
        self.flush_plaintext()?;
        self.flush_close_notify()?;
        if self.state.peer_closed() {
            return Ok(());
        }
        let mut scratch = [0; WRITE_LIMIT];
        loop {
            // SAFETY: SSL is exclusive and scratch is writable for its stated length.
            let (count, status) = unsafe {
                ffi::ERR_clear_error();
                let count = ffi::SSL_read(
                    self.ssl.as_ptr(),
                    scratch.as_mut_ptr().cast(),
                    scratch.len() as i32,
                );
                (count, ffi::SSL_get_error(self.ssl.as_ptr(), count))
            };
            if count > 0 {
                self.plaintext.extend_from_slice(&scratch[..count as usize]);
                continue;
            }
            if status == ffi::SSL_ERROR_ZERO_RETURN {
                self.state.set_peer_closed(true);
                break;
            }
            if would_block(status) {
                break;
            }
            return self.fail(error("TLS record read failed"));
        }
        Ok(())
    }
    fn flush_plaintext(&mut self) -> Result<()> {
        while !self.pending_plaintext.is_empty() {
            // Move the buffer out so encrypt can mutate SSL and failure state
            // while its input remains stable for the duration of SSL_write.
            let mut pending = std::mem::take(&mut self.pending_plaintext);
            let result = self.encrypt(&pending[..pending.len().min(WRITE_LIMIT)]);
            if let Ok(count) = result {
                pending.advance(count);
            }
            self.pending_plaintext = pending;
            if result? == 0 {
                break;
            }
        }
        Ok(())
    }
    fn ciphertext_len(&self) -> usize {
        // SAFETY: SSL owns the output BIO throughout this borrow.
        unsafe { ffi::BIO_ctrl_pending(ffi::SSL_get_wbio(self.ssl.as_ptr())) }
    }
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<usize> {
        if plaintext.is_empty() {
            return Ok(0);
        }
        // SAFETY: SSL is exclusive and copies at most the supplied live bytes.
        let (count, status) = unsafe {
            ffi::ERR_clear_error();
            let count = ffi::SSL_write(
                self.ssl.as_ptr(),
                plaintext.as_ptr().cast(),
                plaintext.len() as i32,
            );
            (count, ffi::SSL_get_error(self.ssl.as_ptr(), count))
        };
        if count > 0 {
            Ok(count as usize)
        } else if would_block(status) {
            Ok(0)
        } else {
            self.fail(error("TLS record write failed"))
        }
    }
    fn flush_close_notify(&mut self) -> Result<()> {
        if !self.state.local_closed()
            || self.state.close_sent()
            || self.is_handshaking()
            || !self.pending_plaintext.is_empty()
        {
            return Ok(());
        }
        // SAFETY: SSL is exclusive. Only the first shutdown sends a notification;
        // its zero result means the receiving direction remains open.
        let (result, status) = unsafe {
            ffi::ERR_clear_error();
            let result = ffi::SSL_shutdown(self.ssl.as_ptr());
            (result, ffi::SSL_get_error(self.ssl.as_ptr(), result))
        };
        if result < 0 && !would_block(status) {
            return self.fail(error("TLS close failed"));
        }
        self.state.set_close_sent(true);
        Ok(())
    }
}
#[inline]
fn would_block(status: i32) -> bool {
    matches!(status, ffi::SSL_ERROR_WANT_READ | ffi::SSL_ERROR_WANT_WRITE)
}
