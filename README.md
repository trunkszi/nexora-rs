# Nexora

Nexora is a Rust 2024 HTTP/1.1, HTTP/2, WebSocket, and TLS library for single-threaded Run-To-Completion
applications. It combines Sans-IO protocols, compile-time declarations, and a nonblocking SDK built on
[liburing-rs](https://github.com/trunkszi/liburing-rs) and [cares-rs](https://github.com/trunkszi/cares-rs).

Applications submit work and explicitly drive completion processing. Runtime handles remain `!Send + !Sync`
on their owning thread; callbacks can capture local state without `Send` bounds. No asynchronous executor is
required, and runtime ownership introduces no `Mutex` lock arbitration. Allocation, reference counting,
parsing, cryptography, and kernel operations retain their own costs.

## Why Nexora?

A client worker may keep HTTP/1.1 connections warm, multiplex requests over
HTTP/2, and consume a WebSocket feed while negotiating TLS for a replacement
connection. Those paths share connection pools, deadlines, and business state.
In a thread-per-core application, moving that state between independently
scheduled tasks can complicate both latency control and ownership.

The usual Rust stack approaches these protocols through asynchronous APIs.
Hyper supports executor adapters, [reqwest's asynchronous client uses Tokio](https://docs.rs/reqwest/latest/reqwest/),
and [tokio-tungstenite integrates WebSockets with Tokio](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/).
Multithreaded task APIs commonly add `Send + 'static` requirements; task handoffs
and work stealing can put scheduler decisions between received bytes and the
client's next action. Bringing that model into an existing synchronous worker
also means introducing asynchronous signatures or maintaining a bridge around
runtime-driven clients.

Nexora brings the protocols back under one worker's control. Its Sans-IO engines
parse HTTP, track HTTP/2 streams, assemble WebSocket messages, and advance rustls
sessions separately from transport I/O. The SDK joins those engines with DNS,
connection pools, and sockets on one caller-owned `liburing::Proactor`. Runtime
handles stay `!Send + !Sync`, and callbacks can retain worker-local state
without making it transferable to another thread. The application chooses when
to apply completions and advance each connection.

This separation is especially useful when a connection stalls. An HTTP/2 window
update, an interleaved WebSocket control frame, or an incomplete TLS handshake
can be inspected as an explicit protocol transition. Breakpoints follow ordinary
calls from completion dispatch into the relevant engine rather than repeatedly
crossing `Future::poll` and executor resume boundaries. The same structure gives
AI-assisted changes a concrete place to handle partial input, cancellation, and
buffer retirement, without inventing borrows or lifetimes across `.await`.
Nexora is designed for clients and shared-nothing workers that need that direct
control over a mixed-protocol connection lifecycle.

## Capabilities

Core capabilities include:

- Zero asynchronous runtime dependencies across all three crates.
- HTTP/1.1 persistence, fixed-length/chunked bodies, bounded reassembly, and
  WebSocket handoff preserving coalesced post-header bytes.
- HTTP/2 multiplexing, HPACK/Huffman, signed flow-control windows, cancellation,
  and GOAWAY draining.
- RFC 6455 masking, fragmented messages, interleaved control frames, and closure.
- Ring-backed rustls TLS 1.3, verified identities, PEM/DER trust, mTLS, and ALPN.
- Shared-ring c-ares DNS, static overrides, origin pools, deadlines, and
  callback-originated submission through a local command inbox.

## Architecture

```text
Application: submit requests / implement services / retain session identifiers
                                |
              nexora-macros: declarations and validated literals
                                |
        nexora: HttpClient / HttpServer / WebSocketClient / callback contexts
                   |                              |
         origin pools and DNS              protocol/session state
                   |                              |
       cares::ProactorResolver       nexora-proto: HTTP1 / H2 / WS / TLS
                   |                              |
                   +------- liburing::Proactor ----+
                              one owning thread
                                     |
                       Linux io_uring completions
```

| Crate | Responsibility | Dependency boundary |
| --- | --- | --- |
| `nexora-proto` | Buffers, HTTP models, URI/headers, Sans-IO codecs and TLS | Independent of `liburing`, `cares`, macros, and SDK |
| `nexora-macros` | Typed construction, routing, WebSocket delegation, literal validation | Generates consumer-side references; no production SDK dependency |
| `nexora` | Proactor integration, DNS, pools, sockets, HTTP/WebSocket clients and servers | Depends on protocols and macros |

Each turn applies completions, advances explicit states, stages I/O and callback commands, then returns to
the application. Scale across threads with a separate ring and separate runtime handles per thread.

## Dependencies and platform

The checkout targets Linux x86_64 and pins its compiler in [rust-toolchain.toml](rust-toolchain.toml).
Runtime execution requires usable io_uring and network access. Native builds need upstream prerequisites; CI
installs CMake, Clang, libclang, pkg-config, and musl tools. Workspace packages have `publish = false`;
consume them from Git:

```toml
[dependencies]
nexora = { git = "https://github.com/trunkszi/nexora-rs.git", branch = "main" }
nexora-proto = { git = "https://github.com/trunkszi/nexora-rs.git", branch = "main" }
```

Macros are re-exported by `nexora`. Generated protocol paths require a direct `nexora-proto` dependency even
when importing macros from the facade. Protocol-only consumers can depend solely on `nexora-proto`. Direct
macro users can add `nexora-macros` from the same source. `#[json_body]` additionally requires `sonic-rs = { version = "0.5.10", default-features = false }` as a direct application dependency.

The root manifest centralizes versions and tracks `liburing`, `liburing-macros`, `cares`, and `cares-macros`
through upstream Git `main` branches. `Cargo.lock` records selected revisions. TLS uses rustls 0.23 with
ring; sessions explicitly select TLS 1.3 even though the workspace enables rustls's TLS 1.2 code.

## Buffers, HTTP models, and errors

`Bytes` provides immutable cheap-clone views. `slice`, `split_to`, and `split_off` share backing storage;
`BytesMut::freeze` transfers an immutable view without copying payload bytes. `BytesMut` supports cursor
advancement, resizing, growth, and big-endian `put_u8/u16/u24/u32/u64`. Mutation detaches shared backing
storage when necessary. Its default capacity is 4096 bytes.

```rust
use nexora_proto::{Bytes, BytesMut};

fn main() {
    let mut input = BytesMut::new();
    input.extend_from_slice(b"headerpayload");
    let header: Bytes = input.split_to(6).freeze();
    let payload = input.freeze();
    assert_eq!(header.as_ref(), b"header");
    assert_eq!(payload.slice(..4).as_ref(), b"payl");
}
```

`Request` owns `Method`, `Uri`, `Version`, `Headers`, and a complete `Bytes` body; `Response` owns
`StatusCode`, version, headers, and body. Constructors include `Request::get/post`, `with_header`,
`with_body`, and `Response::ok/json/text`. JSON responses accept already encoded bytes. `Headers` preserves
repeated fields, normalizes names to ASCII lowercase, and offers `insert`, `append`, `get_all`,
`content_length`, and `is_chunked`. `Uri` handles authority, port, path/query, and redirect resolution;
`Scheme` distinguishes HTTP, HTTPS, WS, and WSS.

Protocol boundaries use `ProtoError`, `Http2ErrorCode`, and `nexora_proto::Result`. Runtime boundaries use
`nexora::Error` and `nexora::Result`, preserving protocol, DNS, kernel, and I/O causes. Handle cancellation,
deadlines, `BodyTooLarge`, closed connections, exhausted pools, redirect limits, and invalid states
explicitly.

## Sans-IO HTTP/1.1

Codecs transform caller-owned buffers without sockets. Decoders return `Ok(None)` for incomplete input and
retain bytes for the next call. Encoding validates a complete message before appending output.

```rust
use nexora_proto::{BytesMut, Http1ClientCodec, Http1ServerCodec, Method, Request, Response};

fn main() -> nexora_proto::Result<()> {
    let mut client = Http1ClientCodec::default();
    let mut server = Http1ServerCodec::default();
    let mut wire = BytesMut::new();
    client.encode_request(&Request::post("http://localhost/echo", "hello")?, &mut wire)?;
    let (request, _) = server.decode_request(&mut wire)?
        .ok_or(nexora_proto::ProtoError::Incomplete)?;
    let response = Response::ok(request.body).with_header("transfer-encoding", "chunked");
    server.encode_response(&response, &mut wire)?;
    let (response, _) = client.decode_response(&mut wire, Method::Post)?
        .ok_or(nexora_proto::ProtoError::Incomplete)?;
    assert_eq!(response.body.as_ref(), b"hello");
    Ok(())
}
```

`Http1ClientConfig` and `Http1ServerConfig` default to 16 KiB headers and 16 MiB bodies. Excessive bodies
return `ProtoError::BodyTooLarge`; excessive headers return `HeaderListTooLarge`. Framing accepts consistent
Content-Length or chunked coding, including extensions and validated trailers. Conflicting lengths and
ambiguous framing fail before consumption. HTTP/1.0 rejects Transfer-Encoding.

`Http1KeepAlive` reports `KeepAlive`, `Close`, or `Upgrade`; `Http1Event` represents completion/upgrade
events. Supply the request method when decoding responses for HEAD and CONNECT semantics. A 101 response or
WebSocket upgrade request consumes exactly through `\r\n\r\n`; pass the remaining buffer to `WebSocketCodec`.
Body-bearing upgrades are rejected. The decoder has no EOF signal and explicitly rejects EOF-delimited
response bodies; use fixed-length or chunked framing.

## HTTP/2 multiplexing, compression, and flow control

`Http2Connection` owns the preface, SETTINGS exchange, compression contexts, streams, reassembly, and queued
output. `Http2Config` combines `Http2Settings` with a 16 MiB default body limit. Server push is disabled by the
connection layer.

```rust
use nexora_proto::{BytesMut, Http2Connection, Http2Event, Request, Response};

fn main() -> nexora_proto::Result<()> {
    let mut client = Http2Connection::client_default();
    let mut server = Http2Connection::server_default();
    for _ in 0..4 {
        let mut wire = BytesMut::new();
        client.take_tx_bytes(&mut wire);
        server.feed_bytes(&mut wire)?;
        server.take_tx_bytes(&mut wire);
        client.feed_bytes(&mut wire)?;
    }
    let first = client.submit_request(&Request::get("https://localhost/one")?)?;
    let second = client.submit_request(&Request::get("https://localhost/two")?)?;
    let mut wire = BytesMut::new();
    client.take_tx_bytes(&mut wire);
    server.feed_bytes(&mut wire)?;
    while let Some(event) = server.poll_event() {
        if let Http2Event::RequestReceived { stream_id, request } = event {
            server.submit_response(stream_id, &Response::ok(request.path()))?;
        }
    }
    server.take_tx_bytes(&mut wire);
    client.feed_bytes(&mut wire)?;
    assert_ne!(first, second);
    let mut completed = 0;
    while let Some(event) = client.poll_event() {
        if let Http2Event::ResponseReceived { response, .. } = event {
            assert!(matches!(response.body.as_ref(), b"/one" | b"/two"));
            completed += 1;
        }
    }
    assert_eq!(completed, 2);
    Ok(())
}
```

Drain `poll_event` for messages, resets, body-limit events, SETTINGS/PING acknowledgements, and GOAWAY.
`can_open_stream` and `active_stream_count` expose admission; `cancel_stream` queues `RST_STREAM(CANCEL)`.
`send_ping`, `send_goaway`, `has_tx_bytes`, and `take_tx_bytes` integrate with the transport. GOAWAY starts
draining already admitted streams while preventing inappropriate new admission.

Connection and stream send windows use signed `i64`. SETTINGS reductions can make stream windows negative;
queued DATA resumes after WINDOW_UPDATE credit. Inspect `connection_send_window` and `stream_send_window` to
diagnose stalls. Flow-control credit and body-size admission are separate limits.

The `http2` module exports `Http2Frame`, `Http2FrameHeader`, `Http2FrameType`, protocol constants, `encode_frame`,
and `decode_frame` for lower-level integrations. `HpackEncoder::encode` appends header blocks;
`HpackDecoder::decode` validates them with table/header limits. Preserve each direction's compression
context. `http2::huffman` exposes `huffman_encode`, `huffman_decode`, and `huffman_encoded_len`; compression
helpers do not create transports or streams.

```rust
use nexora_proto::{BytesMut, HpackDecoder, HpackEncoder};
use nexora_proto::http2::huffman::{huffman_decode, huffman_encode};

fn main() -> nexora_proto::Result<()> {
    let fields = vec![(":method".into(), "GET".into()), (":path".into(), "/".into())];
    let mut block = BytesMut::new();
    HpackEncoder::default().encode(&fields, &mut block);
    assert_eq!(HpackDecoder::default().decode(block.as_ref())?, fields);
    let mut coded = BytesMut::new();
    huffman_encode(b"www.example.com", &mut coded);
    assert_eq!(huffman_decode(coded.as_ref())?, b"www.example.com");
    Ok(())
}
```

## RFC 6455 WebSocket codecs

`WebSocketHandshake` builds and validates upgrades and computes accept keys. `WebSocketCodec` enforces endpoint masking
roles, text UTF-8, limits, and fragment ordering. `WebSocketConfig` defaults to 1 MiB frames and 16 MiB reassembled
messages.

```rust
use nexora_proto::{Bytes, BytesMut, WebSocketCodec, WebSocketFrame, WebSocketMessage, WebSocketOpcode};

fn main() -> nexora_proto::Result<()> {
    let mut client = WebSocketCodec::client_default();
    let mut server = WebSocketCodec::server_default();
    let mut wire = BytesMut::new();
    client.encode_frame(&WebSocketFrame {
        fin: false, opcode: WebSocketOpcode::Text, payload: Bytes::from("hel"),
    }, &mut wire)?;
    client.encode_message(&WebSocketMessage::Ping(Bytes::from("probe")), &mut wire)?;
    client.encode_frame(&WebSocketFrame {
        fin: true, opcode: WebSocketOpcode::Continuation, payload: Bytes::from("lo"),
    }, &mut wire)?;
    assert!(matches!(server.decode_message(&mut wire)?, Some(WebSocketMessage::Ping(_))));
    assert_eq!(server.decode_message(&mut wire)?, Some(WebSocketMessage::Text("hello".into())));
    Ok(())
}
```

`WebSocketMessage` represents Text, Binary, Ping, Pong, and Close. `WebSocketCloseFrame` carries `WebSocketCloseCode` and a
reason. Sans-IO callers own control responses and transport shutdown; runtime clients/servers add automatic
Pong and close progression. Keep the HTTP buffer remainder during upgrades, including a complete first
frame.

## TLS 1.3 sessions and trust

`TlsSession` accepts fragmented/coalesced ciphertext and exposes plaintext and encrypted output. The caller
owns transport and handshake progress:

```rust
use nexora_proto::{AlpnProtocol, BytesMut, TlsClientConfig, TlsServerConfig, TlsSession};

fn main() -> nexora_proto::Result<()> {
    let alpn = [AlpnProtocol::Http11];
    let (identity, certificate) = TlsServerConfig::self_signed_for_localhost(&alpn)?;
    let trust = TlsClientConfig::with_root_certificates(&[certificate], &alpn)?;
    let mut client = TlsSession::new_client(&trust, "localhost")?;
    let mut server = TlsSession::new_server(&identity)?;
    for _ in 0..64 {
        let mut wire = BytesMut::new();
        client.take_ciphertext(&mut wire)?;
        server.feed_ciphertext(wire.as_ref())?;
        wire.clear();
        server.take_ciphertext(&mut wire)?;
        client.feed_ciphertext(wire.as_ref())?;
        if !client.is_handshaking() && !server.is_handshaking()
            && !client.wants_write() && !server.wants_write() { break; }
    }
    assert_eq!(client.alpn_protocol(), Some(AlpnProtocol::Http11));
    assert_eq!(client.write_plaintext(b"hello")?, 5);
    let mut wire = BytesMut::new();
    client.take_ciphertext(&mut wire)?;
    server.feed_ciphertext(wire.as_ref())?;
    let mut plaintext = BytesMut::new();
    server.read_plaintext(&mut plaintext)?;
    assert_eq!(plaintext.as_ref(), b"hello");
    Ok(())
}
```

`feed_ciphertext` returns available plaintext, not consumed ciphertext bytes. `write_plaintext` may accept a
prefix: drain encrypted output and retry the suffix. Drain both handshake directions even without
application data. `role`, `wants_read`, and `wants_write` expose scheduling state. `send_close_notify`
closes local sending; drain accepted plaintext and alerts, allow peer half-close replies, then retire the
transport. Fatal TLS errors remain terminal; queued alerts can still be extracted.

| Configuration API | Policy |
| --- | --- |
| `TlsClientConfig::default()` | Public WebPKI roots; ALPN prefers `h2`, then `http/1.1` |
| `with_root_certificates` / `with_pem_root_certificates` | Replace trust with DER roots or a PEM certificate bundle |
| `with_client_auth` | Add a DER client chain and private key |
| `TlsServerConfig::from_der` | Server chain/key without required client authentication |
| `from_der_with_client_auth` | Require a client identity trusted by supplied DER authorities |
| `self_signed_for_localhost` | Generate a local identity and return its DER trust certificate |
| `TlsClientConfig::insecure_client` | Test policy bypassing trust/name checks; permits impersonation |

Use verified roots and the expected server name in deployed clients. Select `AlpnProtocol::Http2` for H2 and
`Http11` for WebSocket upgrades.

## Compile-time declarations

`HeaderMap` converts named fields through `HeaderMapExt`; values implement `ToString`/`FromStr`.
`RestRequest` generates `into_request` and `build_path_and_query`, percent-encoding path/query values.
Optional query, header, and body fields are omitted when absent.

```rust
use nexora::{HeaderMap, RestRequest, headers, http2_headers};
use nexora_proto::HeaderMapExt;

#[derive(HeaderMap)]
struct Auth {
    #[header(name = "authorization")]
    token: String,
    #[header(name = "x-retry", default = "0")]
    retry: u32,
}
#[derive(RestRequest)]
#[rest(method = "POST", path = "/items/{id}")]
struct Update {
    #[path_param]
    id: u64,
    #[query]
    revision: Option<u32>,
    #[body]
    payload: Vec<u8>,
}
fn main() -> nexora_proto::Result<()> {
    let auth = Auth { token: "Bearer example".into(), retry: 0 }.to_headers();
    let request = Update { id: 42, revision: Some(3), payload: b"new".to_vec() }
        .into_request("https://api.example")?;
    assert_eq!(request.uri.path_and_query(), "/items/42?revision=3");
    let fields = headers! { "accept" => "application/json" };
    let pseudo = http2_headers! { ":method" => "GET", ":path" => "/items" };
    assert!(auth.contains("authorization") && fields.contains("accept"));
    assert_eq!(pseudo.len(), 2);
    Ok(())
}
```

`#[header(required)]` requires an optional header; `default` handles absence. `#[json_body]` serializes
through the consumer's `sonic_rs`; `#[body]` accepts `AsRef<[u8]>`. Literal macros reject invalid names
and control-byte injection at compile time. `http2_headers!` preserves HTTP/2 pseudo-header spelling and field order.
`#[http_service]` and `#[websocket_handler]` generate the runtime implementations below.

## Nonblocking HTTP client and callback re-entry

Use `HttpClient::new` with a `Proactor` and public `ClientConfig`, or `HttpClient::builder().build(&mut
ring)` for defaults. Network and DNS subsystem IDs must be distinct, non-internal, and unique among owners
sharing the ring.

```rust,no_run
use std::{cell::Cell, net::{IpAddr, Ipv4Addr}, rc::Rc, time::Duration};
use nexora::{ClientConfig, HttpClient, Proactor, Request};

fn main() -> nexora::Result<()> {
    let mut ring = Proactor::builder().build()?;
    let mut client = HttpClient::new(&mut ring, ClientConfig::default())?;
    client.resolve_host("app.local", 8080, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let done = Rc::new(Cell::new(false));
    let completed = Rc::clone(&done);
    let followup = Request::get("http://app.local:8080/result")?;
    client.submit(&mut ring, Request::post("http://app.local:8080/start", "begin")?,
        move |ctx, _id, result| {
            if let Err(error) = result {
                eprintln!("start failed: {error}");
                completed.set(true);
                return;
            }
            let finished = Rc::clone(&completed);
            match ctx.submit(followup, move |_ctx, _id, result| {
                if let Err(error) = result { eprintln!("result failed: {error}"); }
                finished.set(true);
            }) {
                Ok(id) => { ctx.set_timer(Duration::from_secs(2), move |ctx, _| ctx.cancel(id)); }
                Err(error) => { eprintln!("admission failed: {error}"); completed.set(true); }
            }
        })?;
    while !done.get() { client.drive(&mut ring)?; }
    client.shutdown(&mut ring);
    ring.shutdown()?;
    Ok(())
}
```

`submit` returns a `RequestId`; admitted requests have one terminal callback. Immediate admission errors
return directly. `cancel` reports whether a pending request was found. `ClientContext` stages submissions,
cancellation, timers, `websocket_send`, and `websocket_close`. Callbacks need neither a `RefCell<HttpClient>` nor a second
mutable borrow of the ring. Commands take effect on later progress.

`ClientConfig` controls pools, connect/request deadlines, redirects, header/body bounds, TLS, and H2
preference. Defaults include 10-second connect, 30-second request, five redirects, 16 KiB headers, and 16
MiB response bodies. Uploads default to unlimited; set `max_request_body_size` to bound them.
A zero `max_body_size` accepts only empty responses and does not restrict uploads.
Set `tls_config: Some(TlsClientConfig::default())` for verified HTTPS. Cleartext H2 requires
`http2_prior_knowledge`; ordinary cleartext requests use HTTP/1.1.

Setting `prefer_http2: false` restricts HTTPS ALPN to HTTP/1.1, including when a
custom TLS policy otherwise offers HTTP/2. `TlsClientConfig::with_alpn` replaces
advertised protocols while retaining certificate trust and client identity.
A policy excluding `http/1.1` rejects a peer that omits ALPN before sending any HTTP request.
HTTP/1.1 fallback requires that protocol to be allowed by the configured TLS policy.
Set `tls_server_name: Some(name)` to override TLS SNI and certificate hostname verification.
The connection target, request URI, HTTP/1.1 Host, and HTTP/2 `:authority` retain the original URI host.
Before dropping a client, call `client.shutdown(&mut ring)` with its live owning
proactor. It cancels pending requests, drains socket and timer completions, and
closes connection descriptors and retires DNS targets and cancellation acknowledgments. The call is
terminal and panics on proactor failure. Shared-ring owners use
`client.shutdown_with(&mut ring, &mut peer_dispatcher)?`; on failure retain both ring and driver and retry.

### Origin pools and DNS

`OriginKey::from_uri` identifies normalized scheme/host/port origins. `OriginPool` is passive
admission/lifecycle state, not a socket owner. It coalesces waiters during resolution/handshake and manages
HTTP/1 slots and H2 stream admission. `PoolConfig` defaults to six connections/six idle entries per origin,
90-second idle expiry, and five-minute lifetime. Observe the client through `active_request_count` and
`idle_connection_count`.

`HostResolver` wraps `cares::ProactorResolver` on the same ring, static overrides, a TTL-bounded `DnsCache`,
and dual-stack queries. `resolve_host` pins addresses before DNS; an empty list removes a pin. IP literals
bypass name queries. `dns_servers_csv` selects servers; `None` reads system configuration. Shared queries
remain alive until their final waiter leaves; usable A/AAAA answers and remaining addresses drive connection
failover.

Direct integrations can use `HostResolver::new/default_resolver`, `start_query`, `cancel_queries`, `flush`,
`on_completion`, and cache accessors. Keep registered operands alive through final CQEs; shut down the ring
through the same dispatcher before dropping an armed resolver. `begin_shutdown` stops DNS submissions;
continue flushing and dispatching until `has_pending_io()` is false. Changing a cache or pin does not itself poll network work.

## Unified HTTP services and deferred responses

Implement `HttpService::call(&mut self, &mut RequestContext, Request, Responder)` directly or generate
routing with `#[http_service]`. Context exposes route parameters, peer address, version, and H2 stream ID.
Immediate macro handlers return `Result<Response>`; deferred handlers own a `Responder` and return
`Result<()>`.

```rust,no_run
use nexora::{http_service, HttpServer, Proactor, Request, RequestContext,
    Responder, Response, ServerConfig};

struct Api { waiting: Option<Responder> }
#[http_service]
impl Api {
    #[route(method = "GET", path = "/health")]
    fn health(&mut self, _ctx: &mut RequestContext, _req: Request) -> nexora::Result<Response> {
        Ok(Response::ok("ready"))
    }
    #[route(method = "POST", path = "/deferred")]
    fn defer(&mut self, _ctx: &mut RequestContext, _req: Request,
        responder: Responder) -> nexora::Result<()> {
        self.waiting = Some(responder);
        Ok(())
    }
    #[route(method = "POST", path = "/complete")]
    fn complete(&mut self, _ctx: &mut RequestContext, _req: Request) -> nexora::Result<Response> {
        if let Some(waiting) = self.waiting.take() { waiting.respond(Response::ok("finished"))?; }
        Ok(Response::ok("completed"))
    }
}
fn main() -> nexora::Result<()> {
    let mut ring = Proactor::builder().build()?;
    let mut server = HttpServer::builder(Api { waiting: None })
        .config(ServerConfig::default())
        .bind(&mut ring, std::net::SocketAddr::from(([127, 0, 0, 1], 8080)))?;
    loop {
        server.drive(&mut ring)?;
        ring.wait_completions(1, Some(std::time::Duration::ZERO), &mut server)?;
    }
}
```

The deferred route retains a responder until a request on another connection calls `/complete`. Application work consumes the responder with
`respond(response)`. Dropping an open unanswered responder queues 500; `is_closed` detects disconnects and
late `respond` returns `ConnectionClosed`. Gateways can retain it while submitting upstream work, then
answer on completion. Retaining it alone does not schedule application work.

`ServerConfig` controls limits, TLS identity, subsystem ID, backlog, and I/O buffer size. A cleartext
listener detects HTTP/1.1, H2C prior knowledge, and HTTP/1.1 WebSocket upgrades. A TLS listener selects H2
or HTTP/1.1 through ALPN, with WebSocket upgrades on HTTP/1.1. It does not sniff mixed plaintext/TLS.

`HttpServer::drive` applies caller-dispatched completions and submits I/O without polling the ring.
Standalone servers use explicit dispatch as above. HTTP/WS client `drive` methods own their DNS/network
routes; use `client.drive_with(&mut ring, &mut server)` when sharing with a server. Compose more owners
with `CompletionRoutes::new(&mut first, &mut second)`, or implement `CompletionDispatcher` on a worker.
Unknown and overlapping routes fail closed. Drivers remain caller-owned; no handler is registered on the ring. `initiate_graceful_shutdown` starts draining;
continue progress before retiring the ring and its operands. `IoUringSocket` and `SocketState` expose
lower-level descriptor, buffer, in-flight, cancellation, and close lifecycle operations.

## WebSocket clients, handlers, and proactive push

`WebSocketClientConfig` and `WebSocketEvent` live in `nexora::websocket_client`. Choose distinct subsystem IDs when combining
HTTP and WS clients; their defaults overlap. For WSS, supply verified TLS configuration offering ALPN
`http/1.1`.

```rust,no_run
use nexora::{Headers, Proactor, WebSocketClient, WebSocketSessionId};
use nexora::websocket_client::{WebSocketClientConfig, WebSocketEvent};

fn connect(ring: &mut Proactor) -> nexora::Result<(WebSocketClient, WebSocketSessionId)> {
    let mut client = WebSocketClient::new(ring, WebSocketClientConfig::default())?;
    let id = client.connect(ring, "ws://127.0.0.1:8080/ws", Headers::new(),
        |ctx, id, result| {
            if result.is_ok() { ctx.websocket_send(id, nexora::WebSocketMessage::Text("hello".into())); }
        })?;
    client.set_message_handler(id, |_ctx, session, event| {
        if let WebSocketEvent::Text(text) = event { println!("{}: {text}", session.id().raw()); }
    })?;
    Ok((client, id))
}
```

The caller repeatedly invokes `client.drive(ring)`. `connect` admits an attempt; its callback reports later
success/failure. Use `is_open`, `send_text`, `send_binary`, `ping`, `pong`, and `close` with the returned
`WebSocketSessionId`. Message callbacks receive a `WebSocketSession`; its send/ping/close methods stage work through
`ClientContext`. `ping_interval` enables configured keepalive pings.

Register server upgrades with `server.with_websocket_handler("/ws", handler)`. Implement `WebSocketUpgradeHandler` or
generate event delegation:

```rust
use nexora::{websocket_handler, WebSocketServerSession};

struct Echo;
#[websocket_handler]
impl Echo {
    #[on_open]
    fn opened(&mut self, session: &mut WebSocketServerSession) -> nexora::Result<()> {
        println!("opened {}", session.id().raw());
        Ok(())
    }
    #[on_text]
    fn text(&mut self, session: &mut WebSocketServerSession, text: String) -> nexora::Result<()> {
        session.send_text(text)
    }
}
```

Handlers select open, message, text, binary, ping, pong, close, and error events. `WebSocketServerSession` exposes
`id`, `peer_addr`, `send`, `send_text`, `send_binary`, and `close`. Save its ID during `on_open`; later
application turns can call `server.websocket_send(id, message)` or `server.websocket_close` for proactive push without
retaining mutable session borrows. The push example uses a caller-loop `Instant` deadline; callback timers
are available through `ClientContext::set_timer`.

## Runnable examples

All four programs in [crates/nexora/examples](crates/nexora/examples) bind ephemeral loopback ports, assert
results, and exit. They require real Linux io_uring; building an example does not establish successful
runtime execution.

| Example | Demonstrated behavior |
| --- | --- |
| `http1_keepalive_and_cares_dns` | Two requests reuse one connection; an unpinned name queries a local UDP/TCP DNS responder |
| `http2_tls_multiplex_and_cancel` | Verified localhost TLS/H2, three completed requests, one pre-poll cancellation |
| `websocket_echo_and_push_timer` | Upgrade, text echo, deadline-triggered server push addressed by session ID |
| `unified_gateway_server` | Sequential HTTP/1.1, H2C, and WS clients share one cleartext listener |

```sh
cargo run -p nexora --example http1_keepalive_and_cares_dns
cargo run -p nexora --example http2_tls_multiplex_and_cancel
cargo run -p nexora --example websocket_echo_and_push_timer
cargo run -p nexora --example unified_gateway_server
```

The DNS example starts controlled mock-peer threads; library progress and callbacks stay on the application
thread. The H2 example cancels before polling; it does not alone demonstrate an active on-wire reset.
Lifecycle tests exercise the separate cancellation stages.

## Build, validation, and test dimensions

Run commands from the repository root. [.cargo/config.toml](.cargo/config.toml) defaults `RUST_TEST_THREADS`
to `1`, serializing ordinary harness execution and CI. Explicit environment values or `--test-threads`
override that default. This does not remove controlled peer threads within individual tests.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

GitHub-hosted CI runs these full-workspace Cargo checks directly, including
formatting, Clippy, tests, doctests, and rustdoc. Keep lockfiles in Cargo's native
generated format. Dependencies use inline tables and authored files remain within
800 lines; generated Cargo.lock is exempt.

| Dimension | Command | Boundary and assertions |
| --- | --- | --- |
| Integration | `cargo test -p nexora --test integration_tests` | Buffers, protocols, macros, trust/ALPN, resolver integration, static pins, size rejection |
| E2E | `cargo test -p nexora --test e2e_tests` | Real loopback SDK requests, multiplexing, callback chains, deferred responses, WebSocket exchanges |
| Lifecycle | `cargo test -p nexora --test lifecycle_tests` | Exactly-once cancellation, completion retirement, responder fallback, drain, drop, resource release |
| Scenario | `cargo test -p nexora --test scenario_tests` | Trickle/bursts, DNS retry/fallback, negative windows, resets, reconnect, slow peers |

Focused protocol and macro checks do not require a live application server:

```sh
cargo test -p nexora-proto
cargo test -p nexora-proto --test bytes_headers_tests
cargo test -p nexora-proto --test http1_tls_tests
cargo test -p nexora-proto --test http2_multiplex_tests
cargo test -p nexora-proto --test hpack_frame_tests
cargo test -p nexora-proto --test websocket_tests
cargo test -p nexora-macros --test macro_tests
cargo test -p nexora-macros --test ui_tests
cargo test -p nexora-proto --release
```

Protocol targets label in-memory integration/E2E/lifecycle/scenario modules; macro targets include
compile-pass and compile-fail fixtures. Runtime targets use controlled peers and real kernel I/O. Keep those
evidence boundaries distinct: unavailable io_uring or native prerequisites are not passing runtime tests.
Generate rustdoc for the complete public API, including lower-level inbox, DNS, pool, socket, and frame
helpers. See [AGENTS.md](AGENTS.md) for maintenance rules.
