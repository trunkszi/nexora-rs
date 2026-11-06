//! Immutable TLS contexts and their retained callback policy.
use std::{
    ffi::{CStr, CString},
    ptr::{self, NonNull},
};

use aws_lc_sys as ffi;

use super::{
    Result,
    certificate::{Bio, Certificate, PrivateKey},
};

#[uarch::cold_sink]
pub(super) fn error(reason: &str) -> super::ProtoError {
    let mut text: [std::ffi::c_char; 256] = [0; 256];
    // SAFETY: the error queue is thread-local and text has the supplied capacity.
    let detail = unsafe {
        let code = ffi::ERR_get_error();
        ffi::ERR_error_string_n(code, text.as_mut_ptr(), text.len());
        CStr::from_ptr(text.as_ptr()).to_string_lossy().into_owned()
    };
    super::ProtoError::Tls(format!("{reason}: {detail}"))
}

#[derive(Debug, Clone)]
pub(super) enum Roots {
    Native,
    Der(std::sync::Arc<Vec<Vec<u8>>>),
    Empty,
}

#[derive(Debug)]
struct AlpnPolicy {
    protocols: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub(super) struct Context {
    pub(super) raw: NonNull<ffi::SSL_CTX>,
    alpn: Box<AlpnPolicy>,
}
// SAFETY: contexts are published only after configuration and never mutated again.
// AWS-LC permits SSL_new concurrently on a shared immutable SSL_CTX.
unsafe impl Send for Context {}
// SAFETY: callback policy is immutable; per-session state belongs to its SSL.
unsafe impl Sync for Context {}
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the context reference; SSL retains its own reference.
        unsafe { ffi::SSL_CTX_free(self.raw.as_ptr()) };
    }
}
impl Context {
    pub(super) fn new(alpn: Vec<Vec<u8>>) -> Result<Self> {
        // SAFETY: TLS_method is static; the returned context is exclusively owned here.
        unsafe {
            let raw = NonNull::new(ffi::SSL_CTX_new(ffi::TLS_method()))
                .ok_or_else(|| error("allocate TLS context"))?;
            let context = Self {
                raw,
                alpn: Box::new(AlpnPolicy { protocols: alpn }),
            };
            let p = raw.as_ptr();
            if ffi::SSL_CTX_set_min_proto_version(p, ffi::TLS1_3_VERSION as u16) != 1
                || ffi::SSL_CTX_set_max_proto_version(p, ffi::TLS1_3_VERSION as u16) != 1
            {
                return Err(error("set TLS 1.3 bounds"));
            }
            ffi::SSL_CTX_set_session_cache_mode(p, ffi::SSL_SESS_CACHE_OFF as _);
            ffi::SSL_CTX_set_options(p, ffi::SSL_OP_NO_TICKET as u32);
            if ffi::SSL_CTX_set_num_tickets(p, 0) != 1 {
                return Err(error("disable session tickets"));
            }
            ffi::SSL_CTX_set_mode(
                p,
                (ffi::SSL_MODE_ENABLE_PARTIAL_WRITE | ffi::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
                    as _,
            );
            Ok(context)
        }
    }
    pub(super) fn client(roots: &Roots, insecure: bool) -> Result<Self> {
        let mut context = Self::new(Vec::new())?;
        context.trust(roots)?;
        context.verify(insecure);
        Ok(context)
    }
    pub(super) fn copy_client(source: &Self, insecure: bool) -> Result<Self> {
        let mut context = Self::new(Vec::new())?;
        // SAFETY: the immutable source store stays live and up_ref creates the
        // reference transferred to the new context, preserving its trust snapshot.
        unsafe {
            let store = ffi::SSL_CTX_get_cert_store(source.raw.as_ptr());
            if ffi::X509_STORE_up_ref(store) != 1 {
                return Err(error("retain client trust store"));
            }
            ffi::SSL_CTX_set_cert_store(context.raw.as_ptr(), store);
        }
        context.verify(insecure);
        Ok(context)
    }
    fn verify(&mut self, insecure: bool) {
        // SAFETY: the context is exclusively configured before publication.
        unsafe {
            if insecure {
                ffi::SSL_CTX_set_custom_verify(
                    self.raw.as_ptr(),
                    ffi::SSL_VERIFY_PEER,
                    Some(accept_certificate),
                );
            } else {
                ffi::SSL_CTX_set_verify(self.raw.as_ptr(), ffi::SSL_VERIFY_PEER, None);
            }
        }
    }

    pub(super) fn trust(&mut self, roots: &Roots) -> Result<()> {
        // SAFETY: configuration has exclusive access to this context and its store.
        unsafe {
            let p = self.raw.as_ptr();
            let store = ffi::SSL_CTX_get_cert_store(p);
            if ffi::X509_STORE_set_flags(store, ffi::X509_V_FLAG_PARTIAL_CHAIN as _) != 1 {
                return Err(error("set trust anchor policy"));
            }
            match roots {
                Roots::Native => {
                    let mut loaded = ffi::SSL_CTX_set_default_verify_paths(p) == 1;
                    for path in [
                        "/etc/ssl/certs/ca-certificates.crt",
                        "/etc/pki/tls/certs/ca-bundle.crt",
                    ] {
                        if std::path::Path::new(path).is_file() {
                            let path = CString::new(path).map_err(|_| error("invalid CA path"))?;
                            loaded |=
                                ffi::SSL_CTX_load_verify_locations(p, path.as_ptr(), ptr::null())
                                    == 1;
                        }
                    }
                    if !loaded {
                        return Err(error("load host trust roots"));
                    }
                }
                Roots::Der(certificates) => {
                    for der in certificates.iter() {
                        let certificate = Certificate::der(der)?;
                        if ffi::X509_STORE_add_cert(store, certificate.0.as_ptr()) != 1 {
                            return Err(error("add trust anchor"));
                        }
                    }
                }
                Roots::Empty => {}
            }
            ffi::ERR_clear_error();
        }
        Ok(())
    }
    pub(super) fn identity(&mut self, chain: &[Vec<u8>], key: &[u8]) -> Result<()> {
        let (leaf, chain) = chain
            .split_first()
            .ok_or_else(|| error("empty certificate chain"))?;
        let leaf = Certificate::der(leaf)?;
        let key = PrivateKey::der(key)?;
        // SAFETY: leaf and key stay live; successful calls retain references. Extra
        // chain references transfer only after SSL_CTX_add_extra_chain_cert succeeds.
        unsafe {
            let p = self.raw.as_ptr();
            if ffi::SSL_CTX_use_certificate(p, leaf.0.as_ptr()) != 1
                || ffi::SSL_CTX_use_PrivateKey(p, key.0.as_ptr()) != 1
                || ffi::SSL_CTX_check_private_key(p) != 1
            {
                return Err(error("invalid TLS identity"));
            }
            for der in chain {
                let cert = Certificate::der(der)?;
                if ffi::SSL_CTX_add_extra_chain_cert(p, cert.0.as_ptr()) != 1 {
                    return Err(error("add identity chain"));
                }
                std::mem::forget(cert);
            }
        }
        Ok(())
    }
    pub(super) fn server(&mut self, roots: Option<&Roots>) -> Result<()> {
        if let Some(roots) = roots {
            self.trust(roots)?;
        }
        // SAFETY: Box keeps ALPN callback data stable across moves. Sessions retain
        // the Context Arc until after SSL_free, so the callback data outlives SSL.
        unsafe {
            let p = self.raw.as_ptr();
            if roots.is_some() {
                ffi::SSL_CTX_set_verify(
                    p,
                    ffi::SSL_VERIFY_PEER | ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                    None,
                );
            }
            ffi::SSL_CTX_set_alpn_select_cb(
                p,
                Some(select_alpn),
                (&*self.alpn as *const AlpnPolicy).cast_mut().cast(),
            );
        }
        Ok(())
    }
}

unsafe extern "C" fn accept_certificate(_: *mut ffi::SSL, _: *mut u8) -> ffi::ssl_verify_result_t {
    // Only the X.509 verdict is bypassed; AWS-LC still verifies CertificateVerify.
    ffi::ssl_verify_result_t_ssl_verify_ok
}
unsafe extern "C" fn select_alpn(
    _: *mut ffi::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    input: *const u8,
    input_len: u32,
    argument: *mut std::ffi::c_void,
) -> i32 {
    // SAFETY: AWS-LC supplies a live offered list and writable output pointers.
    // Context owns the immutable policy for the lifetime of every associated SSL.
    unsafe {
        let preferences = &(*argument.cast::<AlpnPolicy>()).protocols;
        if preferences.is_empty() {
            return ffi::SSL_TLSEXT_ERR_NOACK;
        }
        let offered = std::slice::from_raw_parts(input, input_len as usize);
        for preference in preferences {
            let mut offset = 0;
            while let Some(&len) = offered.get(offset) {
                offset += 1;
                let Some(protocol) = offered.get(offset..offset + usize::from(len)) else {
                    return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
                };
                if protocol == preference {
                    *out = protocol.as_ptr();
                    *out_len = len;
                    return ffi::SSL_TLSEXT_ERR_OK;
                }
                offset += usize::from(len);
            }
        }
        ffi::SSL_TLSEXT_ERR_ALERT_FATAL
    }
}

pub(super) fn pem_roots(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut rest = bytes.trim_ascii();
    let mut roots = Vec::new();
    while !rest.is_empty() {
        let end = b"-----END CERTIFICATE-----";
        if !rest.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err(error("malformed PEM bundle"));
        }
        let stop = rest
            .windows(end.len())
            .position(|part| part == end)
            .ok_or_else(|| error("unterminated PEM certificate"))?
            + end.len();
        let bio = Bio::borrowed(&rest[..stop])?;
        // SAFETY: BIO borrows the complete PEM block until parsing finishes.
        let cert = unsafe {
            ffi::PEM_read_bio_X509_AUX(bio.0.as_ptr(), ptr::null_mut(), None, ptr::null_mut())
        };
        let cert = Certificate(NonNull::new(cert).ok_or_else(|| error("invalid PEM certificate"))?);
        roots.push(cert.to_der()?);
        rest = rest[stop..].trim_ascii();
    }
    if roots.is_empty() {
        return Err(error("PEM bundle contains no certificates"));
    }
    Ok(roots)
}
