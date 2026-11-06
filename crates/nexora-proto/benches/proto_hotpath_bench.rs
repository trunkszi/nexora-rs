use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use nexora_proto::*;
mod support;
use support::zero_alloc;
fn valid<T, E: std::fmt::Debug>(result: std::result::Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("invalid benchmark fixture: {error:?}"),
    }
}
fn protocols(c: &mut Criterion) {
    let request = valid(Request::get("http://example.com/market?symbol=BTCUSDT"));
    let response = Response::new(StatusCode::OK);
    let mut output = BytesMut::with_capacity(8192);
    let mut client = Http1ClientCodec::default();
    let mut server = Http1ServerCodec::default();
    zero_alloc(|| {
        output.clear();
        valid(client.encode_request(&request, &mut output));
    });
    zero_alloc(|| {
        output.clear();
        valid(server.encode_response(&response, &mut output));
    });
    c.bench_function("http1/request_encode", |b| {
        b.iter(|| {
            output.clear();
            valid(client.encode_request(black_box(&request), &mut output));
            black_box(&output);
        })
    });
    c.bench_function("http1/response_encode", |b| {
        b.iter(|| {
            output.clear();
            valid(server.encode_response(black_box(&response), &mut output));
            black_box(&output);
        })
    });
    let mut input = BytesMut::with_capacity(8192);
    c.bench_function("http1/request_decode", |b| b.iter(|| {
        input.clear(); input.extend_from_slice(b"GET /market?symbol=BTCUSDT HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n");
        black_box(valid(server.decode_request(&mut input)))
    }));
    c.bench_function("http1/response_decode", |b| {
        b.iter(|| {
            input.clear();
            input.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            black_box(valid(client.decode_response(&mut input, Method::Get)))
        })
    });
    let mut headers = Headers::with_capacity(32);
    for i in 0..32 {
        headers.insert(format!("x-market-{i}"), "value");
    }
    zero_alloc(|| {
        black_box(headers.get(black_box("X-MARKET-31")));
    });
    c.bench_function("headers/get_mixed_case", |b| {
        b.iter(|| black_box(headers.get(black_box("X-MARKET-31"))))
    });
    c.bench_function("headers/insert_replace", |b| {
        b.iter(|| headers.insert(black_box("X-Market-31"), black_box("next")))
    });
    c.bench_function("uri/parse", |b| {
        b.iter(|| {
            black_box(valid(Uri::parse(black_box(
                "https://EXAMPLE.com:8443/market?symbol=BTCUSDT",
            ))))
        })
    });
    let fields = vec![
        (":method".to_owned(), "GET".to_owned()),
        (":path".to_owned(), "/".to_owned()),
        (":scheme".to_owned(), "https".to_owned()),
        (":authority".to_owned(), "example.com".to_owned()),
    ];
    let mut encoder = HpackEncoder::default();
    encoder.encode(&fields, &mut output);
    zero_alloc(|| {
        output.clear();
        encoder.encode(black_box(&fields), &mut output);
    });
    c.bench_function("http2/hpack_encode_warm", |b| {
        b.iter(|| {
            output.clear();
            encoder.encode(black_box(&fields), &mut output);
            black_box(&output);
        })
    });
    let mut block = BytesMut::with_capacity(1024);
    HpackEncoder::new(0).encode(&fields, &mut block);
    let mut decoder = HpackDecoder::new(0, 8192);
    c.bench_function("http2/hpack_decode", |b| {
        b.iter(|| black_box(valid(decoder.decode(black_box(&block)))))
    });
    let frame = Http2Frame::Ping {
        ack: false,
        opaque_data: *b"12345678",
    };
    zero_alloc(|| {
        output.clear();
        valid(http2::encode_frame(&frame, &mut output));
    });
    c.bench_function("http2/frame_encode", |b| {
        b.iter(|| {
            output.clear();
            valid(http2::encode_frame(black_box(&frame), &mut output));
            black_box(&output);
        })
    });
    let mut wire = BytesMut::with_capacity(32);
    valid(http2::encode_frame(&frame, &mut wire));
    c.bench_function("http2/frame_decode", |b| {
        b.iter(|| {
            input.clear();
            input.extend_from_slice(&wire);
            black_box(valid(http2::decode_frame(&mut input, 16384)))
        })
    });
    for len in [32, 1024, 16384] {
        let payload = Bytes::from(vec![42; len]);
        let frame = WebSocketFrame {
            fin: true,
            opcode: WebSocketOpcode::Binary,
            payload,
        };
        let mut codec = WebSocketCodec::server_default();
        let mut wire = BytesMut::with_capacity(len + 14);
        zero_alloc(|| {
            wire.clear();
            valid(codec.encode_frame(&frame, &mut wire));
        });
        let mut mask_bytes = vec![42; len];
        zero_alloc(|| {
            WebSocketCodec::apply_mask(black_box(&mut mask_bytes), [0x37, 0xfa, 0x21, 0x3d])
        });
        c.bench_function(&format!("websocket/mask/{len}"), |b| {
            b.iter(|| {
                WebSocketCodec::apply_mask(
                    black_box(&mut mask_bytes),
                    black_box([0x37, 0xfa, 0x21, 0x3d]),
                )
            })
        });
        c.bench_function(&format!("websocket/encode/{len}"), |b| {
            b.iter(|| {
                wire.clear();
                valid(codec.encode_frame(black_box(&frame), &mut wire));
                black_box(&wire);
            })
        });
        let mut encoded = BytesMut::with_capacity(len + 14);
        let mut masked = WebSocketCodec::client_default();
        c.bench_function(&format!("websocket/masked_encode/{len}"), |b| {
            b.iter(|| {
                encoded.clear();
                valid(masked.encode_frame(black_box(&frame), &mut encoded));
                black_box(&encoded);
            })
        });
        valid(masked.encode_frame(&frame, &mut encoded));
        let mut receive = BytesMut::with_capacity(len + 14);
        c.bench_function(&format!("websocket/masked_decode/{len}"), |b| {
            b.iter(|| {
                receive.clear();
                receive.extend_from_slice(&encoded);
                black_box(valid(codec.decode_message(&mut receive)))
            })
        });
    }
}
criterion_group!(benches, protocols);
criterion_main!(benches);
