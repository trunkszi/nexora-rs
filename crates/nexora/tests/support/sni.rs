//! Native ClientHello observation without an HTTP server or accepted certificate.
use std::{
    cell::RefCell,
    ffi::CStr,
    io::{self, Read},
    ptr::NonNull,
    rc::Rc,
};

use aws_lc_sys as ffi;

pub struct SniProbe {
    ctx: NonNull<ffi::SSL_CTX>,
    ssl: Option<NonNull<ffi::SSL>>,
    seen: Rc<RefCell<Option<String>>>,
}
impl Drop for SniProbe {
    fn drop(&mut self) {
        // SAFETY: SSL owns its BIOs and is freed before its context/callback state.
        unsafe {
            if let Some(ssl) = self.ssl {
                ffi::SSL_free(ssl.as_ptr());
            }
            ffi::SSL_CTX_free(self.ctx.as_ptr());
        }
    }
}
impl SniProbe {
    pub fn new() -> io::Result<Self> {
        // SAFETY: the method is static; every successful allocation is guarded.
        unsafe {
            let ctx = NonNull::new(ffi::SSL_CTX_new(ffi::TLS_method())).ok_or_else(failed)?;
            let mut probe = Self {
                ctx,
                ssl: None,
                seen: Rc::new(RefCell::new(None)),
            };
            if ffi::SSL_CTX_set_tlsext_servername_callback(ctx.as_ptr(), Some(observe)) != 1
                || ffi::SSL_CTX_set_tlsext_servername_arg(
                    ctx.as_ptr(),
                    Rc::as_ptr(&probe.seen).cast_mut().cast(),
                ) != 1
            {
                return Err(failed());
            }
            let ssl = NonNull::new(ffi::SSL_new(ctx.as_ptr())).ok_or_else(failed)?;
            probe.ssl = Some(ssl);
            let input = ffi::BIO_new(ffi::BIO_s_mem());
            let output = ffi::BIO_new(ffi::BIO_s_mem());
            if input.is_null() || output.is_null() {
                ffi::BIO_free(input);
                ffi::BIO_free(output);
                return Err(failed());
            }
            ffi::SSL_set_bio(ssl.as_ptr(), input, output);
            ffi::SSL_set_accept_state(ssl.as_ptr());
            Ok(probe)
        }
    }
    pub fn read_tls(&mut self, stream: &mut impl Read) -> io::Result<usize> {
        let mut input = [0; 16_384];
        let count = stream.read(&mut input)?;
        let ssl = self.ssl.ok_or_else(failed)?;
        // SAFETY: the input slice is live; BIO copies it, and callbacks run only
        // during this synchronous handshake call on the owning test thread.
        unsafe {
            if ffi::BIO_write(
                ffi::SSL_get_rbio(ssl.as_ptr()),
                input.as_ptr().cast(),
                count as i32,
            ) != count as i32
            {
                return Err(failed());
            }
            ffi::ERR_clear_error();
            let result = ffi::SSL_do_handshake(ssl.as_ptr());
            let status = ffi::SSL_get_error(ssl.as_ptr(), result);
            if self.seen.borrow().is_none()
                && result != 1
                && !matches!(status, ffi::SSL_ERROR_WANT_READ | ffi::SSL_ERROR_WANT_WRITE)
            {
                return Err(failed());
            }
        }
        Ok(count)
    }
    pub fn server_name(&self) -> Option<String> {
        self.seen.borrow().clone()
    }
}
unsafe extern "C" fn observe(
    ssl: *mut ffi::SSL,
    _: *mut i32,
    argument: *mut std::ffi::c_void,
) -> i32 {
    // SAFETY: AWS-LC provides the live SSL; the Rc-backed callback state outlives it.
    unsafe {
        let name = ffi::SSL_get_servername(ssl, ffi::TLSEXT_NAMETYPE_host_name);
        if !name.is_null() {
            let state = &*argument.cast::<RefCell<Option<String>>>();
            let Ok(mut state) = state.try_borrow_mut() else {
                return ffi::SSL_TLSEXT_ERR_ALERT_FATAL;
            };
            *state = Some(CStr::from_ptr(name).to_string_lossy().into_owned());
        }
    }
    ffi::SSL_TLSEXT_ERR_OK
}
fn failed() -> io::Error {
    io::Error::other("AWS-LC ClientHello probe failed")
}
