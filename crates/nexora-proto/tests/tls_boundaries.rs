//! Resource erasure and error-queue boundaries at the public TLS API.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use nexora_proto::{AlpnProtocol, TlsServerConfig};

struct ErasureProbe;
static TARGET: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static ERASED: AtomicBool = AtomicBool::new(false);
static OBSERVED: AtomicBool = AtomicBool::new(false);

// SAFETY: allocations delegate to System. Before deallocation, the probe reads
// only a registered, fully initialized allocation with its original layout.
unsafe impl GlobalAlloc for ErasureProbe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: System receives the caller's unchanged valid layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if TARGET
            .compare_exchange(pointer, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // SAFETY: the registered Vec initialized every allocated byte;
            // this allocation remains live until System.dealloc below.
            let zeroed =
                unsafe { (0..layout.size()).all(|index| pointer.add(index).read_volatile() == 0) };
            ERASED.store(zeroed, Ordering::SeqCst);
            OBSERVED.store(true, Ordering::SeqCst);
        }
        // SAFETY: this allocation/layout came from this allocator's System delegate.
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: ErasureProbe = ErasureProbe;

#[test]
fn empty_client_roots_erase_owned_key() {
    let mut key = vec![0xa5; 32];
    assert_eq!(key.capacity(), key.len());
    TARGET.store(key.as_mut_ptr(), Ordering::SeqCst);
    assert!(
        TlsServerConfig::from_der_with_client_auth(Vec::new(), key, &[], &[AlpnProtocol::Http11])
            .is_err()
    );
    assert!(
        OBSERVED.load(Ordering::SeqCst),
        "private key allocation was not released"
    );
    assert!(
        ERASED.load(Ordering::SeqCst),
        "private key bytes survived the error path"
    );
}

#[test]
fn stale_error_queue_preserves_tls_progress() -> nexora_proto::Result<()> {
    use nexora_proto::{BytesMut, TlsClientConfig, TlsSession};
    fn seed_error() {
        // SAFETY: ERR_put_error copies scalar metadata into this thread's queue.
        unsafe {
            aws_lc_sys::ERR_put_error(
                aws_lc_sys::ERR_LIB_USER,
                0,
                42,
                c"TLS boundary test".as_ptr(),
                1,
            )
        };
    }
    fn transfer(sender: &mut TlsSession, receiver: &mut TlsSession) -> nexora_proto::Result<()> {
        let mut wire = BytesMut::new();
        sender.take_ciphertext(&mut wire)?;
        if !wire.is_empty() {
            seed_error();
            receiver.feed_ciphertext(&wire)?;
        }
        Ok(())
    }
    let alpn = [AlpnProtocol::Http11];
    let (identity, certificate) = TlsServerConfig::self_signed_for_localhost(&alpn)?;
    let policy = TlsClientConfig::with_root_certificates(&[certificate], &alpn)?;
    seed_error();
    let mut client = TlsSession::new_client(&policy, "localhost")?;
    let mut server = TlsSession::new_server(&identity)?;
    for _ in 0..16 {
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    seed_error();
    assert_eq!(client.write_plaintext(b"queue survives")?, 14);
    transfer(&mut client, &mut server)?;
    let mut plain = BytesMut::new();
    assert_eq!(server.read_plaintext(&mut plain)?, 14);
    assert_eq!(plain.as_slice(), b"queue survives");
    seed_error();
    client.send_close_notify();
    transfer(&mut client, &mut server)?;
    assert!(!server.wants_read());
    Ok(())
}
