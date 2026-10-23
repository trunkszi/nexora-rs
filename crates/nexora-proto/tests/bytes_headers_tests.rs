//! In-memory buffer, header, URI and TLS trust contracts. The HTTP codec E2E
//! boundary ends with a decoded response; TLS tests drive authenticated sessions
//! through byte buffers. These tests do not exercise sockets or the runtime.

use std::{
    ops::Bound,
    panic::{AssertUnwindSafe, catch_unwind},
};

use nexora_proto::{
    AlpnProtocol, Bytes, BytesMut, Headers, Http1ClientCodec, Http1KeepAlive, Http1ServerCodec,
    Method, ProtoError, Request, Response, Result, Scheme, StatusCode, TlsClientConfig,
    TlsServerConfig, TlsSession, Uri,
};

#[test]
fn integration_tests_shared_byte_views_reach_header_fields() -> Result<()> {
    let mut raw = BytesMut::with_capacity(64);
    raw.extend_from_slice(b"content-length: 5\r\nhello");
    let original = raw.as_ptr();
    let head = raw.split_to(19).freeze();
    assert_eq!(head.as_ptr(), original);
    assert_eq!(raw.as_ptr(), original.wrapping_add(19));
    let body_pointer = raw.as_ptr();
    let body = raw.freeze();
    assert_eq!(body.as_ptr(), body_pointer);
    assert_eq!(body.as_slice(), b"hello");
    let mut headers = Headers::new();
    headers.append("Content-Length", "5");
    assert_eq!(headers.content_length()?, Some(body.len()));
    assert_eq!(head.as_slice(), b"content-length: 5\r\n");
    Ok(())
}

#[test]
fn integration_tests_immutable_slices_and_splits_share_backing() {
    let backing = Vec::from(&b"0123456789"[..]);
    let pointer = backing.as_ptr();
    let bytes = Bytes::from(backing);
    assert_eq!(bytes.as_ptr(), pointer);
    let clone = bytes.clone();
    let bounded = bytes.slice((Bound::Excluded(1), Bound::Included(6)));
    assert_eq!(bounded.as_slice(), b"23456");
    assert_eq!(bounded.as_ptr(), pointer.wrapping_add(2));
    assert_eq!(clone.as_ptr(), pointer);
    let mut view = bytes.slice(1..9);
    let prefix = view.split_to(2);
    let suffix = view.split_off(3);
    assert_eq!(prefix.as_slice(), b"12");
    assert_eq!(view.as_slice(), b"345");
    assert_eq!(suffix.as_slice(), b"678");
    assert_eq!(prefix.as_ptr(), pointer.wrapping_add(1));
    assert_eq!(view.as_ptr(), pointer.wrapping_add(3));
    assert_eq!(suffix.as_ptr(), pointer.wrapping_add(6));
    assert_eq!(bytes.slice(..).as_slice(), b"0123456789");
    assert!(bytes.slice(10..).is_empty());
    static STATIC: &[u8] = b"static";
    assert_eq!(Bytes::from_static(STATIC).as_ptr(), STATIC.as_ptr());
}

#[test]
fn integration_tests_header_replacement_and_removal_keep_other_fields() {
    let mut headers = Headers::with_capacity(4);
    headers.append("X-Token", "old");
    headers.append("Set-Cookie", "a=1");
    headers.append("x-TOKEN", "duplicate");
    headers.append("SET-COOKIE", "b=2");
    assert_eq!(headers.get_all("set-COOKIE"), ["a=1", "b=2"]);
    headers.insert("X-TOKEN", "new");
    assert_eq!(headers.get_all("x-token"), ["new"]);
    assert_eq!(headers.get("X-TOKEN"), Some("new"));
    let names: Vec<_> = headers.iter().map(|field| field.name.as_str()).collect();
    assert_eq!(names, ["x-token", "set-cookie", "set-cookie"]);
    assert_eq!(headers.remove("SET-cookie"), Some("a=1".to_owned()));
    assert!(!headers.contains("set-cookie"));
    assert_eq!(headers.len(), 1);
    assert_eq!(headers.byte_size(), "x-token".len() + "new".len());
    assert_eq!(headers.remove("absent"), None);
}

#[test]
fn e2e_tests_in_memory_http1_request_response_closed_loop() -> Result<()> {
    let mut client = Http1ClientCodec::default();
    let mut server = Http1ServerCodec::default();
    let mut outbound = BytesMut::new();
    let mut inbound = BytesMut::new();
    let request = Request::post("http://example.test/items?sort=asc", "payload")?
        .with_header("X-Request-Id", "42");
    client.encode_request(&request, &mut outbound)?;
    let (received, persistence) = server
        .decode_request(&mut outbound)?
        .ok_or(ProtoError::Incomplete)?;
    assert_eq!(persistence, Http1KeepAlive::KeepAlive);
    assert_eq!(received.uri.path_and_query(), "/items?sort=asc");
    assert_eq!(received.headers.get("HOST"), Some("example.test"));
    assert_eq!(received.headers.get("x-request-id"), Some("42"));
    assert_eq!(received.body.as_slice(), b"payload");
    let response = Response::ok(received.body).with_header("X-Request-Id", "42");
    server.encode_response(&response, &mut inbound)?;
    let (delivered, persistence) = client
        .decode_response(&mut inbound, Method::Post)?
        .ok_or(ProtoError::Incomplete)?;
    assert_eq!(delivered.status, StatusCode::OK);
    assert_eq!(delivered.body.as_slice(), b"payload");
    assert_eq!(delivered.headers.get("X-REQUEST-ID"), Some("42"));
    assert_eq!(persistence, Http1KeepAlive::KeepAlive);
    assert!(outbound.is_empty());
    assert!(inbound.is_empty());
    Ok(())
}

#[test]
fn lifecycle_tests_shared_buffers_survive_mutation_and_owner_drop() {
    let mut buffer = BytesMut::with_capacity(16);
    buffer.extend_from_slice(b"prefix-body");
    let pointer = buffer.as_ptr();
    let mut prefix = buffer.split_to(7);
    let frozen = buffer.clone().freeze();
    assert_eq!(frozen.as_ptr(), pointer.wrapping_add(7));
    prefix.as_mut_slice()[0] = b'P';
    buffer.as_mut_slice()[0] = b'B';
    assert_eq!(prefix.as_slice(), b"Prefix-");
    assert_eq!(buffer.as_slice(), b"Body");
    assert_eq!(frozen.as_slice(), b"body");
    assert_ne!(buffer.as_ptr(), frozen.as_ptr());
    buffer.clear();
    buffer.extend_from_slice(b"replacement");
    drop(buffer);
    drop(prefix);
    assert_eq!(frozen.as_slice(), b"body");
    let mut retained = frozen.clone();
    retained.clear();
    assert!(retained.is_empty());
    assert_eq!(frozen.as_slice(), b"body");
}

#[test]
fn lifecycle_tests_header_clear_and_reuse_does_not_restore_old_values() -> Result<()> {
    let mut headers = Headers::new();
    headers.append("Content-Length", "7");
    headers.append("X-Session", "old");
    let retained = headers.clone();
    headers.clear();
    assert!(headers.is_empty());
    assert_eq!(headers.content_length()?, None);
    headers.insert("content-length", "3");
    assert_eq!(headers.content_length()?, Some(3));
    assert!(!headers.contains("X-Session"));
    assert_eq!(retained.content_length()?, Some(7));
    assert_eq!(retained.get("x-session"), Some("old"));
    Ok(())
}

#[test]
fn scenario_tests_content_length_duplicate_validation() -> Result<()> {
    let mut headers = Headers::new();
    assert_eq!(headers.content_length()?, None);
    headers.append("Content-Length", " 5,\t005 ");
    headers.append("CONTENT-LENGTH", "5");
    assert_eq!(headers.content_length()?, Some(5));
    headers.append("content-length", "6");
    assert!(headers.content_length().is_err());
    for value in [
        "",
        " ",
        "+5",
        "-1",
        "0x10",
        "1 2",
        "1,",
        ",1",
        "1\n",
        "1\r\n",
        "99999999999999999999999999999999999999",
    ] {
        let mut headers = Headers::new();
        headers.append("content-length", value);
        assert!(headers.content_length().is_err(), "accepted {value:?}");
    }
    Ok(())
}

#[test]
fn scenario_tests_transfer_coding_requires_a_final_exact_token() {
    let mut headers = Headers::new();
    for value in [
        "xchunked",
        "chunkedx",
        "chunked;foo=bar",
        "chunked, gzip",
        "chunked,",
    ] {
        headers.insert("Transfer-Encoding", value);
        assert!(!headers.is_chunked(), "accepted {value:?}");
    }
    headers.insert("TRANSFER-ENCODING", "gzip");
    headers.append("transfer-encoding", "\tChUnKeD ");
    assert!(headers.is_chunked());
    headers.append("transfer-encoding", "identity");
    assert!(!headers.is_chunked());
}

#[test]
fn scenario_tests_uri_scheme_authority_and_fragment_boundaries() -> Result<()> {
    let uri = Uri::parse("HtTpS://EXAMPLE.test:8443/path/to?x=1?y=2#ignored")?;
    assert_eq!(uri.scheme(), Scheme::Https);
    assert_eq!(uri.host(), "example.test");
    assert_eq!(uri.port(), 8443);
    assert_eq!(uri.authority(), "example.test:8443");
    assert_eq!(uri.path(), "/path/to");
    assert_eq!(uri.query(), Some("x=1?y=2"));
    assert_eq!(uri.as_str(), "https://example.test:8443/path/to?x=1?y=2");
    for (raw, scheme, port) in [
        ("http://example.test", Scheme::Http, 80),
        ("https://example.test?x", Scheme::Https, 443),
        ("ws://example.test", Scheme::WebSocket, 80),
        ("wss://example.test", Scheme::WebSocketSecure, 443),
    ] {
        let parsed = Uri::parse(raw)?;
        assert_eq!(parsed.scheme(), scheme);
        assert_eq!(parsed.port(), port);
        assert_eq!(parsed.path(), "/");
    }
    let ipv6 = Uri::parse("https://[2001:db8::1]:443/a")?;
    assert_eq!(ipv6.host(), "2001:db8::1");
    assert_eq!(ipv6.authority(), "[2001:db8::1]:443");
    assert_eq!(Uri::parse("http://[::1]")?.authority(), "[::1]");
    Ok(())
}

#[test]
fn scenario_tests_redirects_follow_relative_resolution_rules() -> Result<()> {
    let base = Uri::parse("http://example.test/a/b/c?old=1")?;
    for (reference, expected) in [
        ("../d?new=2", "http://example.test/a/d?new=2"),
        ("./d", "http://example.test/a/b/d"),
        ("/d/./e/../", "http://example.test/d/"),
        ("../../../d", "http://example.test/d"),
        ("?new=2", "http://example.test/a/b/c?new=2"),
        ("#part", "http://example.test/a/b/c?old=1"),
        ("", "http://example.test/a/b/c?old=1"),
        ("//OTHER.test:81/x", "http://other.test:81/x"),
        ("https://other.test/x/../y#part", "https://other.test/y"),
        ("%2e%2e/d", "http://example.test/a/b/%2e%2e/d"),
        ("g//h/../i", "http://example.test/a/b/g//i"),
    ] {
        assert_eq!(
            base.resolve_redirect(reference)?.as_str(),
            expected,
            "{reference}"
        );
    }
    Ok(())
}

#[test]
fn scenario_tests_uri_rejects_ambiguous_or_malformed_authorities() {
    for raw in [
        "",
        "/path",
        "ftp://example.test/a",
        "http:///path",
        "http://user@example.test/",
        "http://example.test:",
        "http://example.test:0",
        "http://example.test:65536",
        "http://example.test:-1",
        "http://example.test:+80",
        "http://example.test:80:90",
        "http://::1/",
        "http://[::1",
        "http://[]/",
        "http://[example.test]/",
        "http://[::1]junk/",
        "http://[::1]:80junk/",
        "http://exa mple.test/",
        "http://example.test/\r\nInjected:yes",
        "http://example.test/\\other",
        "http://example.test/%GG",
    ] {
        assert!(Uri::parse(raw).is_err(), "accepted {raw:?}");
    }
}

#[test]
fn scenario_tests_network_order_growth_and_cursor_reuse() {
    let mut buffer = BytesMut::with_capacity(1);
    buffer.put_u8(1);
    buffer.put_u16(0x0203);
    buffer.put_u24(0x040506);
    buffer.put_u32(0x0708090a);
    buffer.put_u64(0x0b0c0d0e0f101112);
    assert_eq!(buffer.as_slice(), &(1..=18).collect::<Vec<_>>());
    buffer.advance(10);
    buffer.reserve(32);
    buffer.put_slice(b"tail");
    assert_eq!(
        buffer.as_slice(),
        &[11, 12, 13, 14, 15, 16, 17, 18, b't', b'a', b'i', b'l']
    );
    let pointer = buffer.as_ptr();
    let whole = buffer.split().freeze();
    assert_eq!(whole.as_ptr(), pointer);
    assert!(buffer.is_empty());
    buffer.resize(3, 0xaa);
    assert_eq!(buffer.as_slice(), [0xaa; 3]);
    assert_eq!(
        whole.as_slice(),
        &[11, 12, 13, 14, 15, 16, 17, 18, b't', b'a', b'i', b'l']
    );
}

#[test]
fn scenario_tests_invalid_ranges_panic_without_corrupting_views() {
    let mut bytes = Bytes::from("abc");
    assert!(catch_unwind(|| bytes.slice(4..)).is_err());
    assert!(catch_unwind(|| bytes.slice((Bound::Included(2), Bound::Excluded(1)))).is_err());
    assert!(catch_unwind(|| bytes.slice(..=usize::MAX)).is_err());
    assert!(catch_unwind(|| bytes.slice((Bound::Excluded(usize::MAX), Bound::Unbounded))).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| bytes.split_to(4))).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| bytes.split_off(4))).is_err());
    assert_eq!(bytes.as_slice(), b"abc");
    let mut mutable = BytesMut::new();
    mutable.put_slice(b"abc");
    assert!(catch_unwind(AssertUnwindSafe(|| mutable.advance(4))).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| mutable.split_to(4))).is_err());
    assert_eq!(mutable.as_slice(), b"abc");
}

#[test]
fn scenario_tests_shared_cursor_growth_preserves_frozen_survivors() {
    let mut buffer = BytesMut::with_capacity(8);
    buffer.extend_from_slice(b"abcdefgh");
    let frozen = buffer.clone().freeze();
    buffer.advance(3);
    let mut tail = buffer.clone();
    buffer.reserve(64);
    buffer.extend_from_slice(b"ijkl");
    tail.as_mut_slice()[0] = b'D';
    assert_eq!(buffer.as_slice(), b"defghijkl");
    assert_eq!(tail.as_slice(), b"Defgh");
    assert_eq!(frozen.as_slice(), b"abcdefgh");
    assert_ne!(buffer.as_ptr(), frozen.as_ptr().wrapping_add(3));
}

#[test]
fn lifecycle_tests_consumed_capacity_compacts_and_clear_reuses_storage() {
    let mut buffer = BytesMut::with_capacity(16);
    buffer.extend_from_slice(b"abcdefgh");
    let allocation = buffer.as_ptr();
    let capacity = buffer.capacity();
    buffer.advance(5);
    buffer.reserve(capacity - buffer.len());
    assert_eq!(buffer.as_slice(), b"fgh");
    assert_eq!(buffer.as_ptr(), allocation);
    assert_eq!(buffer.capacity(), capacity);
    buffer.extend_from_slice(b"ijk");
    assert_eq!(buffer.as_slice(), b"fghijk");
    buffer.clear();
    buffer.extend_from_slice(b"new");
    assert_eq!(buffer.as_ptr(), allocation);
    assert_eq!(buffer.as_slice(), b"new");
    assert_eq!(buffer.capacity(), capacity);
}

#[test]
fn lifecycle_tests_shared_shrink_regrowth_hides_removed_and_neighboring_bytes() {
    let mut suffix = BytesMut::with_capacity(16);
    suffix.extend_from_slice(b"abcdefgh");
    let original = suffix.clone().freeze();
    let mut prefix = suffix.split_to(4);
    prefix.resize(2, b'!');
    prefix.resize(5, b'z');
    prefix.as_mut()[0] = b'A';
    suffix.advance(2);
    suffix.resize(4, b'q');
    suffix[0] = b'G';
    assert_eq!(prefix.as_slice(), b"Abzzz");
    assert_eq!(suffix.as_slice(), b"Ghqq");
    assert_eq!(original.as_slice(), b"abcdefgh");
    drop(prefix);
    drop(suffix);
    assert_eq!(original.as_slice(), b"abcdefgh");
}

#[test]
fn scenario_tests_capacity_overflow_panics_preserve_shared_views() {
    let mut buffer = BytesMut::with_capacity(16);
    buffer.extend_from_slice(b"prefix-body");
    buffer.advance(7);
    let original = buffer.clone().freeze();
    let pointer = buffer.as_ptr();
    let capacity = buffer.capacity();
    assert!(catch_unwind(AssertUnwindSafe(|| buffer.reserve(usize::MAX))).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| buffer.resize(usize::MAX, 0))).is_err());
    assert_eq!(buffer.as_slice(), b"body");
    assert_eq!(buffer.as_ptr(), pointer);
    assert_eq!(buffer.capacity(), capacity);
    buffer.put_slice(b"!");
    assert_eq!(buffer.as_slice(), b"body!");
    assert_eq!(original.as_slice(), b"body");
}

#[test]
fn scenario_tests_fragment_and_query_redirects_preserve_inherited_paths() -> Result<()> {
    let base = Uri::parse("http://example.test/a/../b?old")?;
    assert_eq!(base.resolve_redirect("#fragment")?.as_str(), base.as_str());
    assert_eq!(
        base.resolve_redirect("?new")?.as_str(),
        "http://example.test/a/../b?new"
    );
    Ok(())
}

#[test]
fn scenario_tests_uri_components_reject_unescaped_non_uri_characters() -> Result<()> {
    let base = Uri::parse("http://example.test/base")?;
    for invalid in ["|", "{", "}", "\"", "^", "`", "[", "]", "\u{e9}"] {
        for reference in [
            format!("/path{invalid}tail"),
            format!("/path?query={invalid}"),
            format!("/path#fragment{invalid}"),
        ] {
            assert!(
                Uri::parse(&format!("http://example.test{reference}")).is_err(),
                "accepted absolute URI component {reference:?}"
            );
            assert!(
                base.resolve_redirect(&reference).is_err(),
                "accepted redirect component {reference:?}"
            );
        }
    }
    for reference in [
        "/path#fragment#again",
        "?q=ok#fragment#again",
        "#fragment#again",
    ] {
        assert!(Uri::parse(&format!("http://example.test{reference}")).is_err());
        assert!(base.resolve_redirect(reference).is_err());
    }
    let reserved = "/!$&'()*+,;=:@/%7B%7D%5B%5D%C3%A9?q=/?:@!$&'()*+,;=";
    let uri = Uri::parse(&format!("http://example.test{reserved}"))?;
    assert_eq!(uri.path_and_query(), reserved);
    assert_eq!(base.resolve_redirect(reserved)?.path_and_query(), reserved);
    Ok(())
}

fn certificate_error(error: impl std::fmt::Display) -> ProtoError {
    ProtoError::Tls(error.to_string())
}

fn tls_handshake(
    client_policy: &TlsClientConfig,
    server_policy: &TlsServerConfig,
) -> Result<(TlsSession, TlsSession)> {
    let mut client = TlsSession::new_client(client_policy, "localhost")?;
    let mut server = TlsSession::new_server(server_policy)?;
    for _ in 0..128 {
        tls_transfer(&mut client, &mut server)?;
        tls_transfer(&mut server, &mut client)?;
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok((client, server));
        }
    }
    Err(ProtoError::Tls(
        "in-memory handshake did not complete".into(),
    ))
}

fn tls_transfer(sender: &mut TlsSession, receiver: &mut TlsSession) -> Result<()> {
    let mut wire = BytesMut::new();
    sender.take_ciphertext(&mut wire)?;
    for fragment in wire.chunks(7) {
        receiver.feed_ciphertext(fragment)?;
    }
    Ok(())
}

#[test]
fn integration_tests_pem_trust_authenticates_fragmented_tls_exchange() -> Result<()> {
    let identity =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(certificate_error)?;
    let alpn = [AlpnProtocol::Http2, AlpnProtocol::Http11];
    let server = TlsServerConfig::from_der(
        vec![identity.cert.der().to_vec()],
        identity.key_pair.serialize_der(),
        &alpn,
    )?;
    let client =
        TlsClientConfig::with_pem_root_certificates(identity.cert.pem().as_bytes(), &alpn)?;
    let (mut client, mut server) = tls_handshake(&client, &server)?;
    assert_eq!(client.alpn_protocol(), Some(AlpnProtocol::Http2));
    let payload = b"authenticated with a PEM trust anchor";
    assert_eq!(client.write_plaintext(payload)?, payload.len());
    tls_transfer(&mut client, &mut server)?;
    let mut delivered = BytesMut::new();
    assert_eq!(server.read_plaintext(&mut delivered)?, payload.len());
    assert_eq!(delivered.as_slice(), payload);
    for invalid in [
        b"".as_slice(),
        b"not a certificate",
        b"-----BEGIN CERTIFICATE-----\n!bad!\n-----END CERTIFICATE-----\n",
    ] {
        assert!(TlsClientConfig::with_pem_root_certificates(invalid, &alpn).is_err());
    }
    let poisoned = format!(
        "{}-----BEGIN CERTIFICATE-----\n!bad!\n-----END CERTIFICATE-----\n",
        identity.cert.pem()
    );
    assert!(TlsClientConfig::with_pem_root_certificates(poisoned.as_bytes(), &alpn).is_err());
    Ok(())
}

#[test]
fn scenario_tests_mtls_rejects_missing_untrusted_and_wrong_usage_clients() -> Result<()> {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    let ca_key = KeyPair::generate().map_err(certificate_error)?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(certificate_error)?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = ca_params.self_signed(&ca_key).map_err(certificate_error)?;
    let server_identity =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(certificate_error)?;
    let server_der = server_identity.cert.der().to_vec();
    let ca_der = ca.der().to_vec();
    let alpn = [AlpnProtocol::Http11];
    let server = TlsServerConfig::from_der_with_client_auth(
        vec![server_der.clone()],
        server_identity.key_pair.serialize_der(),
        std::slice::from_ref(&ca_der),
        &alpn,
    )?;
    let anonymous =
        TlsClientConfig::with_root_certificates(std::slice::from_ref(&server_der), &alpn)?;
    assert!(matches!(
        tls_handshake(&anonymous, &server),
        Err(ProtoError::Tls(_))
    ));
    for (usage, accepted) in [
        (ExtendedKeyUsagePurpose::ClientAuth, true),
        (ExtendedKeyUsagePurpose::ServerAuth, false),
    ] {
        let key = KeyPair::generate().map_err(certificate_error)?;
        let mut params =
            CertificateParams::new(vec!["client.test".into()]).map_err(certificate_error)?;
        params.extended_key_usages = vec![usage];
        let cert = params
            .signed_by(&key, &ca, &ca_key)
            .map_err(certificate_error)?;
        let authenticated = anonymous.clone().with_client_auth(
            vec![cert.der().to_vec(), ca_der.clone()],
            key.serialize_der(),
        )?;
        let pair = tls_handshake(&authenticated, &server);
        if accepted {
            let (mut client, mut server) = pair?;
            let body = b"mutually authenticated bytes";
            assert_eq!(client.write_plaintext(body)?, body.len());
            tls_transfer(&mut client, &mut server)?;
            let mut received = BytesMut::new();
            assert_eq!(server.read_plaintext(&mut received)?, body.len());
            assert_eq!(received.as_slice(), body);
        } else {
            assert!(matches!(pair, Err(ProtoError::Tls(_))));
        }
        let wrong_key = KeyPair::generate().map_err(certificate_error)?;
        assert!(
            anonymous
                .clone()
                .with_client_auth(vec![cert.der().to_vec()], wrong_key.serialize_der())
                .is_err()
        );
    }
    let outsider = rcgen::generate_simple_self_signed(vec!["untrusted.test".into()])
        .map_err(certificate_error)?;
    let untrusted = anonymous.with_client_auth(
        vec![outsider.cert.der().to_vec()],
        outsider.key_pair.serialize_der(),
    )?;
    assert!(matches!(
        tls_handshake(&untrusted, &server),
        Err(ProtoError::Tls(_))
    ));
    assert!(
        TlsServerConfig::from_der_with_client_auth(
            vec![server_der],
            server_identity.key_pair.serialize_der(),
            &[],
            &alpn
        )
        .is_err()
    );
    Ok(())
}
