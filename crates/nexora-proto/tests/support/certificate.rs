//! Independently issued AWS-LC fixtures for trust, identity and EKU checks.
use std::{
    ffi::{CStr, CString},
    ptr::{self, NonNull},
};

use aws_lc_sys as ffi;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nexora_proto::{ProtoError, Result};

pub struct Identity {
    pub der: Vec<u8>,
    pub key: Vec<u8>,
}
struct X509(NonNull<ffi::X509>);
impl Drop for X509 {
    fn drop(&mut self) {
        // SAFETY: this guard owns the certificate reference.
        unsafe { ffi::X509_free(self.0.as_ptr()) };
    }
}
struct Key(NonNull<ffi::EVP_PKEY>);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: this guard owns the key reference.
        unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
    }
}
fn error() -> ProtoError {
    ProtoError::Tls(String::from("certificate fixture failed"))
}
fn x509(der: &[u8]) -> Result<X509> {
    let mut cursor = der.as_ptr();
    // SAFETY: the complete DER slice is readable and cursor is writable.
    NonNull::new(unsafe { ffi::d2i_X509(ptr::null_mut(), &mut cursor, der.len() as _) })
        .map(X509)
        .ok_or_else(error)
}
fn key(der: &[u8]) -> Result<Key> {
    let mut cursor = der.as_ptr();
    // SAFETY: the complete DER slice is readable and cursor is writable.
    NonNull::new(unsafe { ffi::d2i_AutoPrivateKey(ptr::null_mut(), &mut cursor, der.len() as _) })
        .map(Key)
        .ok_or_else(error)
}
fn extension(cert: &X509, nid: i32, value: &CStr) -> Result<()> {
    // SAFETY: the value is NUL-terminated and X509 is exclusively configured here.
    unsafe {
        let ext = ffi::X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, value.as_ptr());
        if ext.is_null() {
            return Err(error());
        }
        let result = ffi::X509_add_ext(cert.0.as_ptr(), ext, -1);
        ffi::X509_EXTENSION_free(ext);
        if result != 1 {
            return Err(error());
        }
    }
    Ok(())
}
impl Identity {
    pub fn pkcs8_key(&self) -> Result<Vec<u8>> {
        let key = key(&self.key)?;
        // SAFETY: key is live and each allocated PKCS8 reference is released once.
        unsafe {
            let info = ffi::EVP_PKEY2PKCS8(key.0.as_ptr());
            if info.is_null() {
                return Err(error());
            }
            let size = ffi::i2d_PKCS8_PRIV_KEY_INFO(info, ptr::null_mut());
            if size <= 0 {
                ffi::PKCS8_PRIV_KEY_INFO_free(info);
                return Err(error());
            }
            let mut bytes = vec![0; size as usize];
            let count = ffi::i2d_PKCS8_PRIV_KEY_INFO(info, &mut bytes.as_mut_ptr());
            ffi::PKCS8_PRIV_KEY_INFO_free(info);
            if count != size {
                return Err(error());
            }
            Ok(bytes)
        }
    }
    pub fn remove_san(&mut self) -> Result<()> {
        let certificate = x509(&self.der)?;
        let private = key(&self.key)?;
        // SAFETY: the certificate is exclusively owned; its deleted extension is
        // detached before freeing, and the new signature uses the matching key.
        unsafe {
            let p = certificate.0.as_ptr();
            let index = ffi::X509_get_ext_by_NID(p, ffi::NID_subject_alt_name, -1);
            if index < 0 {
                return Err(error());
            }
            ffi::X509_EXTENSION_free(ffi::X509_delete_ext(p, index));
            if ffi::X509_sign(p, private.0.as_ptr(), ffi::EVP_sha256()) <= 0 {
                return Err(error());
            }
            let size = ffi::i2d_X509(p, ptr::null_mut());
            if size <= 0 {
                return Err(error());
            }
            let mut bytes = vec![0; size as usize];
            if ffi::i2d_X509(p, &mut bytes.as_mut_ptr()) != size {
                return Err(error());
            }
            self.der = bytes;
            Ok(())
        }
    }

    pub fn pem(&self) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(&self.der)
        )
    }
    pub fn issue(host: &str, issuer: Option<&Self>, ca: bool, usage: &CStr) -> Result<Self> {
        let host = CString::new(host).map_err(|_| error())?;
        // SAFETY: every native reference is guarded, all configuration is exclusive,
        // and serialization buffers are sized using the corresponding i2d function.
        unsafe {
            let ec = ffi::EC_KEY_new_by_curve_name(ffi::NID_X9_62_prime256v1);
            if ec.is_null() {
                return Err(error());
            }
            let generated = ffi::EC_KEY_generate_key(ec);
            let private = NonNull::new(ffi::EVP_PKEY_new()).map(Key);
            let used = private
                .as_ref()
                .is_some_and(|p| ffi::EVP_PKEY_set1_EC_KEY(p.0.as_ptr(), ec) == 1);
            ffi::EC_KEY_free(ec);
            let private = private.ok_or_else(error)?;
            if generated != 1 || !used {
                return Err(error());
            }
            let cert = X509(NonNull::new(ffi::X509_new()).ok_or_else(error)?);
            let p = cert.0.as_ptr();
            if ffi::X509_set_version(p, 2) != 1
                || ffi::ASN1_INTEGER_set(ffi::X509_get_serialNumber(p), 42) != 1
                || ffi::X509_gmtime_adj(ffi::X509_getm_notBefore(p), -60).is_null()
                || ffi::X509_gmtime_adj(ffi::X509_getm_notAfter(p), 86_400).is_null()
                || ffi::X509_set_pubkey(p, private.0.as_ptr()) != 1
            {
                return Err(error());
            }
            let subject = ffi::X509_get_subject_name(p);
            if ffi::X509_NAME_add_entry_by_txt(
                subject,
                c"CN".as_ptr(),
                ffi::MBSTRING_ASC as _,
                host.as_ptr().cast(),
                -1,
                -1,
                0,
            ) != 1
            {
                return Err(error());
            }
            let authority = issuer.map(|issuer| x509(&issuer.der)).transpose()?;
            let signing_key = issuer.map(|issuer| key(&issuer.key)).transpose()?;
            let name = authority
                .as_ref()
                .map_or(subject, |c| ffi::X509_get_subject_name(c.0.as_ptr()));
            if ffi::X509_set_issuer_name(p, name) != 1 {
                return Err(error());
            }
            extension(
                &cert,
                ffi::NID_basic_constraints,
                if ca {
                    c"critical,CA:TRUE"
                } else {
                    c"critical,CA:FALSE"
                },
            )?;
            extension(
                &cert,
                ffi::NID_key_usage,
                if ca {
                    c"critical,keyCertSign,cRLSign,digitalSignature"
                } else {
                    c"critical,digitalSignature"
                },
            )?;
            if !ca {
                extension(&cert, ffi::NID_ext_key_usage, usage)?;
                let san =
                    CString::new(format!("DNS:{}", host.to_string_lossy())).map_err(|_| error())?;
                extension(&cert, ffi::NID_subject_alt_name, &san)?;
            }
            let signer = signing_key.as_ref().unwrap_or(&private);
            if ffi::X509_sign(p, signer.0.as_ptr(), ffi::EVP_sha256()) <= 0 {
                return Err(error());
            }
            let size = ffi::i2d_X509(p, ptr::null_mut());
            let key_size = ffi::i2d_PrivateKey(private.0.as_ptr(), ptr::null_mut());
            if size <= 0 || key_size <= 0 {
                return Err(error());
            }
            let mut der = vec![0; size as usize];
            let mut key = vec![0; key_size as usize];
            if ffi::i2d_X509(p, &mut der.as_mut_ptr()) != size
                || ffi::i2d_PrivateKey(private.0.as_ptr(), &mut key.as_mut_ptr()) != key_size
            {
                return Err(error());
            }
            Ok(Self { der, key })
        }
    }
}
