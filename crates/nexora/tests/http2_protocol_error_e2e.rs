//! A raw loopback H2 peer supplies a compressed header list beyond the receive cap.

mod support;

use std::{
    cell::RefCell,
    io::{Read, Write},
    net::TcpListener,
    rc::Rc,
    time::Duration,
};

use nexora::{
    BytesMut, Error, Http2ErrorCode, HttpClient, Request,
    proto::{
        ProtoError,
        http2::{
            CLIENT_PREFACE, HpackDecoder, HpackEncoder, Http2Frame, Http2Settings, encode_frame,
        },
    },
};
use support::{IntoCheck, TestResult, check};

#[test]
fn e2e_lifecycle_scenario_oversized_hpack_preserves_protocol_error_on_all_active_streams()
-> TestResult {
    let _exclusive = support::exclusive();
    let limit = 65_536;
    let mut fields = vec![(String::from(":status"), String::from("200"))];
    fields.extend((0..80).map(|_| (String::from("x-padding"), "a".repeat(1024))));
    let mut compressed = BytesMut::new();
    HpackEncoder::default().encode(&fields, &mut compressed);
    check(
        compressed.len() < 16_384,
        "compressed block must fit one HEADERS frame",
    )?;
    check(
        matches!(HpackDecoder::new(4096, limit).decode(compressed.as_slice()), Err(ProtoError::HeaderListTooLarge { size, max }) if size > limit && max == limit),
        "decoded headers must exceed the advertised receive cap",
    )?;

    let compressed = compressed.as_slice().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").t()?;
    let address = listener.local_addr().t()?;
    let peer = std::thread::spawn(move || -> TestResult {
        let (mut socket, _) = listener.accept().t()?;
        socket.set_read_timeout(Some(Duration::from_secs(3))).t()?;
        socket.set_write_timeout(Some(Duration::from_secs(3))).t()?;
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).t()?;
        check(preface == *CLIENT_PREFACE, "H2 prior-knowledge preface")?;
        let mut initial = BytesMut::new();
        encode_frame(
            &Http2Frame::Settings {
                ack: false,
                settings: Http2Settings {
                    enable_push: false,
                    ..Http2Settings::default()
                },
            },
            &mut initial,
        )
        .t()?;
        socket.write_all(initial.as_slice()).t()?;
        let mut streams = Vec::new();
        while streams.len() < 3 {
            let mut header = [0; 9];
            socket.read_exact(&mut header).t()?;
            let length = (usize::from(header[0]) << 16)
                | (usize::from(header[1]) << 8)
                | usize::from(header[2]);
            let mut payload = vec![0; length];
            socket.read_exact(&mut payload).t()?;
            if header[3] == 1 {
                let id =
                    u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
                streams.push(id);
            }
        }
        check(
            streams == [1, 3, 5],
            "all three requests must be in flight on one connection",
        )?;
        let mut response = BytesMut::new();
        encode_frame(
            &Http2Frame::Headers {
                stream_id: 1,
                end_stream: true,
                end_headers: true,
                header_block: nexora::Bytes::copy_from_slice(&compressed),
            },
            &mut response,
        )
        .t()?;
        socket.write_all(response.as_slice()).t()?;
        let mut discard = [0; 4096];
        loop {
            match socket.read(&mut discard) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    });

    let mut ring = support::proactor().t()?;
    let mut config = support::client_config(1, 2).t()?;
    config.http2_prior_knowledge = true;
    config.max_header_list_size = limit;
    let mut client = HttpClient::new(&mut ring, config).t()?;
    let outcomes = Rc::new(RefCell::new(Vec::new()));
    for _ in 0..3 {
        let outcomes = Rc::clone(&outcomes);
        client
            .submit(
                &mut ring,
                Request::get(&format!("http://{address}/")).t()?,
                move |_, id, result| outcomes.borrow_mut().push((id, result)),
            )
            .t()?;
    }
    let settled = support::drive_until(
        &mut ring,
        |ring| {
            client.drive(ring)?;
            Ok(outcomes.borrow().len() == 3)
        },
        Duration::from_secs(3),
    )
    .t()?;
    client.shutdown(&mut ring);
    peer.join()
        .map_err(|_| String::from("raw H2 peer panicked"))??;
    check(
        settled && outcomes.borrow().len() == 3,
        "every affected stream must complete exactly once",
    )?;
    let expected = ProtoError::Http2StreamError {
        stream_id: 1,
        code: Http2ErrorCode::EnhanceYourCalm,
        reason: String::from("header list too large"),
    };
    for (_, result) in outcomes.borrow().iter() {
        check(
            matches!(result, Err(Error::Proto(error)) if error == &expected),
            format!("original HPACK protocol error lost: {result:?}"),
        )?;
    }
    check(
        client.active_request_count() == 0,
        "all failed streams must retire",
    )
}
