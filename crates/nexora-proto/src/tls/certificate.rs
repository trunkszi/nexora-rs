//! Owned X.509, key and memory-BIO operands.
use std::{
    ffi::c_int,
    ptr::{self, NonNull},
};

use aws_lc_sys as ffi;

use super::{Result, context::error};

pub(super) struct Bio<'a>(
    pub(super) NonNull<ffi::BIO>,
    std::marker::PhantomData<&'a [u8]>,
);
impl<'a> Bio<'a> {
    pub(super) fn borrowed(bytes: &'a [u8]) -> Result<Self> {
        let len = isize::try_from(bytes.len()).map_err(|_| error("certificate too large"))?;
        // SAFETY: callers keep bytes alive until parsing and BIO_free finish.
        NonNull::new(unsafe { ffi::BIO_new_mem_buf(bytes.as_ptr().cast(), len) })
            .map(|raw| Self(raw, std::marker::PhantomData))
            .ok_or_else(|| error("allocate certificate BIO"))
    }
}
impl Drop for Bio<'_> {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the BIO and releases it exactly once.
        unsafe { ffi::BIO_free(self.0.as_ptr()) };
    }
}
pub(super) struct Certificate(pub(super) NonNull<ffi::X509>);
impl Certificate {
    pub(super) fn der(bytes: &[u8]) -> Result<Self> {
        let len =
            std::ffi::c_long::try_from(bytes.len()).map_err(|_| error("certificate too large"))?;
        let mut cursor = bytes.as_ptr();
        // SAFETY: the decoder reads at most len live bytes and updates only cursor.
        let raw = unsafe { ffi::d2i_X509(ptr::null_mut(), &mut cursor, len) };
        let certificate = Self(NonNull::new(raw).ok_or_else(|| error("invalid DER certificate"))?);
        if cursor != bytes.as_ptr().wrapping_add(bytes.len()) {
            return Err(error("trailing DER certificate bytes"));
        }
        Ok(certificate)
    }
    pub(super) fn to_der(&self) -> Result<Vec<u8>> {
        // SAFETY: i2d_X509 reports the size before writing to the allocated buffer.
        unsafe { encode(|out| ffi::i2d_X509(self.0.as_ptr(), out)) }
    }
}
impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one X509 reference.
        unsafe { ffi::X509_free(self.0.as_ptr()) };
    }
}
pub(super) struct PrivateKey(pub(super) NonNull<ffi::EVP_PKEY>);
impl PrivateKey {
    pub(super) fn der(bytes: &[u8]) -> Result<Self> {
        let len =
            std::ffi::c_long::try_from(bytes.len()).map_err(|_| error("private key too large"))?;
        let mut cursor = bytes.as_ptr();
        // SAFETY: the decoder reads at most len bytes and returns an owned key.
        let raw = unsafe { ffi::d2i_AutoPrivateKey(ptr::null_mut(), &mut cursor, len) };
        let key = Self(NonNull::new(raw).ok_or_else(|| error("invalid DER private key"))?);
        if cursor != bytes.as_ptr().wrapping_add(bytes.len()) {
            return Err(error("trailing private key bytes"));
        }
        Ok(key)
    }
}
impl Drop for PrivateKey {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one EVP_PKEY reference.
        unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
    }
}
pub(super) struct Secret(pub(super) Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: the live Vec owns this writable buffer until cleansing completes.
        unsafe { ffi::OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}
unsafe fn encode(mut write: impl FnMut(*mut *mut u8) -> c_int) -> Result<Vec<u8>> {
    let size = write(ptr::null_mut());
    if size <= 0 {
        return Err(error("measure DER encoding"));
    }
    let mut bytes = Secret(vec![0; size as usize]);
    let mut cursor = bytes.0.as_mut_ptr();
    if write(&mut cursor) != size {
        return Err(error("serialize DER"));
    }
    Ok(std::mem::take(&mut bytes.0))
}

pub(super) fn localhost() -> Result<(Vec<u8>, Secret)> {
    // SAFETY: all allocated references are immediately wrapped; mutable X509 and
    // key operations are exclusive until the certificate is signed and serialized.
    unsafe {
        let ec = NonNull::new(ffi::EC_KEY_new_by_curve_name(ffi::NID_X9_62_prime256v1))
            .ok_or_else(|| error("allocate P-256 key"))?;
        let generated = ffi::EC_KEY_generate_key(ec.as_ptr());
        let key = NonNull::new(ffi::EVP_PKEY_new()).map(PrivateKey);
        let attached = key
            .as_ref()
            .is_some_and(|key| ffi::EVP_PKEY_set1_EC_KEY(key.0.as_ptr(), ec.as_ptr()) == 1);
        ffi::EC_KEY_free(ec.as_ptr());
        let key = key.ok_or_else(|| error("allocate private key"))?;
        if generated != 1 || !attached {
            return Err(error("generate P-256 key"));
        }
        let cert = Certificate(
            NonNull::new(ffi::X509_new()).ok_or_else(|| error("allocate certificate"))?,
        );
        let p = cert.0.as_ptr();
        let mut serial = [0; 4];
        aws_lc_rs::rand::fill(&mut serial).map_err(|_| error("generate certificate serial"))?;
        let serial = (u32::from_be_bytes(serial) & 0x7fff_ffff).max(1);
        if ffi::X509_set_version(p, 2) != 1
            || ffi::ASN1_INTEGER_set(ffi::X509_get_serialNumber(p), serial.into()) != 1
            || ffi::X509_gmtime_adj(ffi::X509_getm_notBefore(p), -60).is_null()
            || ffi::X509_gmtime_adj(ffi::X509_getm_notAfter(p), 31_536_000).is_null()
            || ffi::X509_set_pubkey(p, key.0.as_ptr()) != 1
        {
            return Err(error("configure certificate"));
        }
        let name = ffi::X509_get_subject_name(p);
        if ffi::X509_NAME_add_entry_by_txt(
            name,
            c"CN".as_ptr(),
            ffi::MBSTRING_ASC as _,
            c"localhost".as_ptr().cast(),
            -1,
            -1,
            0,
        ) != 1
            || ffi::X509_set_issuer_name(p, name) != 1
        {
            return Err(error("set certificate identity"));
        }
        for (nid, value) in [
            (
                ffi::NID_subject_alt_name,
                c"DNS:localhost,IP:127.0.0.1,IP:::1",
            ),
            (ffi::NID_basic_constraints, c"critical,CA:FALSE"),
            (ffi::NID_key_usage, c"critical,digitalSignature"),
            (ffi::NID_ext_key_usage, c"serverAuth"),
        ] {
            let extension =
                ffi::X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, value.as_ptr());
            if extension.is_null() {
                return Err(error("build certificate extension"));
            }
            let added = ffi::X509_add_ext(p, extension, -1);
            ffi::X509_EXTENSION_free(extension);
            if added != 1 {
                return Err(error("add certificate extension"));
            }
        }
        if ffi::X509_sign(p, key.0.as_ptr(), ffi::EVP_sha256()) <= 0 {
            return Err(error("sign certificate"));
        }
        let private = Secret(encode(|out| ffi::i2d_PrivateKey(key.0.as_ptr(), out))?);
        Ok((cert.to_der()?, private))
    }
}
