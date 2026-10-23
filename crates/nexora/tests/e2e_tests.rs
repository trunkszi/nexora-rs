mod support;

use std::{
    cell::{Cell, RefCell},
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
    time::Duration,
};

use nexora::{
    AlpnProtocol, Bytes, Headers, HttpClient, HttpServer, Method, OriginKey, Request, Response,
    StatusCode, WebSocketClient, WebSocketMessage, WebSocketSessionId, proto::Scheme,
    websocket_client::WebSocketEvent,
};
use support::{
    DnsPlan, Gate, GateMode, IntoCheck, MockDns, Slot, TestResult, WebSocketEcho, check,
    client_config, drive_until, localhost_identity, proactor, server_config, websocket_config,
};

fn show(error: impl ToString) -> String {
    error.to_string()
}

fn drive_two(
    ring: &mut nexora::Proactor,
    server: &mut HttpServer<Gate>,
    client: &mut HttpClient,
    ready: impl Fn() -> bool,
    budget: Duration,
) -> nexora::Result<bool> {
    drive_until(
        ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut *server)?;
            Ok(ready())
        },
        budget,
    )
}

fn body_of(
    slot: &Slot<std::result::Result<Response, nexora::Error>>,
) -> std::result::Result<Vec<u8>, String> {
    let response = slot
        .take()
        .ok_or_else(|| String::from("missing response"))
        .t()?
        .map_err(show)
        .t()?;
    check(response.status == StatusCode::OK, "expected 200").t()?;
    Ok(response.body.as_slice().to_vec())
}

#[test]
fn e2e_01_http1_methods_chunked_keepalive_and_https() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let gate = Gate::new(GateMode::Echo);
    let hits = gate.hits();
    let mode = gate.mode();
    let mut server =
        HttpServer::bind(&mut ring, support::ephemeral(), server_config(3).t()?, gate).t()?;
    let port = server.local_addr().port();
    let mut client = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let samples = [
        (Method::Get, Bytes::new(), &b"ok"[..]),
        (
            Method::Post,
            Bytes::copy_from_slice(br#"{"n":1}"#),
            &br#"{"n":1}"#[..],
        ),
        (Method::Put, Bytes::copy_from_slice(b"put"), &b"put"[..]),
        (Method::Delete, Bytes::copy_from_slice(b"del"), &b"del"[..]),
    ];
    for (method, body, expect) in samples {
        let mut request = Request::post(&format!("http://127.0.0.1:{port}/echo"), body)
            .map_err(show)
            .t()?;
        request.method = method;
        let slot = Slot::new();
        let done = slot.clone();
        client
            .submit(&mut ring, request, move |_ctx, _id, result| {
                done.set(result)
            })
            .map_err(show)
            .t()?;
        check(
            drive_two(
                &mut ring,
                &mut server,
                &mut client,
                || slot.calls() > 0,
                Duration::from_secs(2),
            )
            .t()?,
            "method exchange timed out",
        )
        .t()?;
        check(body_of(&slot).t()?.as_slice() == expect, "method body").t()?;
    }
    mode.set(GateMode::Chunked);
    let slot = Slot::new();
    let done = slot.clone();
    let chunked = Request::post(
        &format!("http://127.0.0.1:{port}/echo"),
        Bytes::copy_from_slice(b"chunk"),
    )
    .map_err(show)
    .t()?;
    client
        .submit(&mut ring, chunked, move |_ctx, _id, result| {
            done.set(result)
        })
        .map_err(show)
        .t()?;
    check(
        drive_two(
            &mut ring,
            &mut server,
            &mut client,
            || slot.calls() > 0,
            Duration::from_secs(2),
        )
        .t()?,
        "chunked exchange timed out",
    )
    .t()?;
    check(body_of(&slot).t()?.as_slice() == b"chunk", "chunked body").t()?;
    let origin = OriginKey::new(Scheme::Http, "127.0.0.1", port);
    check(
        client.idle_connection_count(&origin) >= 1,
        "keep-alive idle connection",
    )
    .t()?;
    check(
        hits.get() >= 5,
        "method and chunked requests hit the service",
    )
    .t()?;

    let identity = localhost_identity(&[AlpnProtocol::Http2, AlpnProtocol::Http11]).t()?;
    let mut tls_server_config = server_config(6).t()?;
    tls_server_config.tls = Some(identity.server);
    let secure_gate = Gate::new(GateMode::Echo);
    let mut secure = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        tls_server_config,
        secure_gate,
    )
    .t()?;
    let secure_port = secure.local_addr().port();
    let mut secure_config = client_config(4, 5).t()?;
    secure_config.tls_config = Some(identity.client);
    let mut secure_client = HttpClient::new(&mut ring, secure_config).t()?;
    let slot = Slot::new();
    let done = slot.clone();
    let https = Request::get(&format!("https://localhost:{secure_port}/echo"))
        .map_err(show)
        .t()?;
    secure_client.resolve_host(
        "localhost",
        secure_port,
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    );
    secure_client
        .submit(&mut ring, https, move |_ctx, _id, result| {
            if let Ok(response) = &result {
                assert_eq!(response.version, nexora::Version::Http11);
            }
            done.set(result);
        })
        .map_err(show)
        .t()?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            secure.drive(ring)?;
            secure_client.drive_with(ring, &mut secure)?;
            Ok(slot.calls() > 0)
        },
        Duration::from_secs(3),
    )
    .t()?;
    check(finished, "https timed out").t()?;
    check(body_of(&slot).t()?.as_slice() == b"ok", "https echo")
}

#[test]
fn e2e_02_h2c_and_tls_multiplex_at_least_32_streams() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let config = server_config(3).t()?;
    let gate = Gate::new(GateMode::Echo);
    let mut server = HttpServer::bind(&mut ring, support::ephemeral(), config, gate).t()?;
    let port = server.local_addr().port();
    let mut client_cfg = client_config(1, 2).t()?;
    client_cfg.http2_prior_knowledge = true;
    client_cfg.prefer_http2 = true;
    let mut client = HttpClient::new(&mut ring, client_cfg).t()?;
    let bodies = Rc::new(RefCell::new(Vec::new()));
    let pending = Rc::new(Cell::new(0u32));
    for index in 0..32u8 {
        let bodies = Rc::clone(&bodies);
        let pending = Rc::clone(&pending);
        let request = Request::post(
            &format!("http://127.0.0.1:{port}/echo"),
            Bytes::copy_from_slice(&[index]),
        )
        .map_err(show)
        .t()?;
        client
            .submit(&mut ring, request, move |_ctx, _id, result| {
                if let Ok(response) = result {
                    bodies.borrow_mut().push(response.body.as_slice().to_vec());
                }
                pending.set(pending.get().saturating_add(1));
            })
            .map_err(show)
            .t()?;
    }
    let finished = drive_two(
        &mut ring,
        &mut server,
        &mut client,
        || pending.get() == 32,
        Duration::from_secs(4),
    )
    .t()?;
    check(finished, "h2c multiplex timed out").t()?;
    check(bodies.borrow().len() == 32, "32 h2c bodies").t()?;

    client.shutdown_with(&mut ring, &mut server).t()?;
    let identity = localhost_identity(&[AlpnProtocol::Http2, AlpnProtocol::Http11]).t()?;
    let mut tls_config = server_config(6).t()?;
    tls_config.tls = Some(identity.server);
    let mut tls_server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        tls_config,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let tls_port = tls_server.local_addr().port();
    let mut tls_client_cfg = client_config(4, 5).t()?;
    tls_client_cfg.tls_config = Some(identity.client);
    tls_client_cfg.prefer_http2 = true;
    let mut tls_client = HttpClient::new(&mut ring, tls_client_cfg).t()?;
    tls_client.resolve_host("localhost", tls_port, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let tls_done = Rc::new(Cell::new(0u32));
    for _ in 0..32 {
        let tls_done = Rc::clone(&tls_done);
        let request = Request::get(&format!("https://localhost:{tls_port}/echo"))
            .map_err(show)
            .t()?;
        tls_client
            .submit(&mut ring, request, move |_ctx, _id, result| {
                if result.is_ok() {
                    tls_done.set(tls_done.get().saturating_add(1));
                }
            })
            .map_err(show)
            .t()?;
    }
    let finished = drive_until(
        &mut ring,
        |ring| {
            tls_server.drive(ring)?;
            tls_client.drive_with(
                ring,
                &mut nexora::CompletionRoutes::new(&mut tls_server, &mut server),
            )?;
            Ok(tls_done.get() == 32)
        },
        Duration::from_secs(4),
    )
    .t()?;
    check(finished && tls_done.get() == 32, "tls h2 multiplex")
}

#[test]
fn e2e_03_callback_submits_the_next_step_and_a_timer() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let port = server.local_addr().port();
    let mut client = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let stage = Rc::new(Cell::new(0u8));
    let stage_done = Rc::clone(&stage);
    let auth = Request::post(
        &format!("http://127.0.0.1:{port}/echo"),
        Bytes::copy_from_slice(b"auth"),
    )
    .map_err(show)
    .t()?;
    client
        .submit(&mut ring, auth, move |ctx, _id, result| {
            if result.is_err() {
                return;
            }
            stage_done.set(1);
            let fetch = match Request::get(&format!("http://127.0.0.1:{port}/echo")) {
                Ok(request) => request,
                Err(_) => return,
            };
            let stage_fetch = Rc::clone(&stage_done);
            if ctx
                .submit(fetch, move |ctx, _id, result| {
                    if result.is_err() {
                        return;
                    }
                    stage_fetch.set(2);
                    let stage_audit = Rc::clone(&stage_fetch);
                    let port = port;
                    ctx.set_timer(Duration::from_millis(1), move |ctx, _timer| {
                        let audit = match Request::post(
                            &format!("http://127.0.0.1:{port}/echo"),
                            Bytes::copy_from_slice(b"audit"),
                        ) {
                            Ok(request) => request,
                            Err(_) => return,
                        };
                        let stage_audit_cb = Rc::clone(&stage_audit);
                        if ctx
                            .submit(audit, move |_ctx, _id, result| {
                                if result.is_ok() {
                                    stage_audit_cb.set(3);
                                }
                            })
                            .is_err()
                        {
                            stage_audit.set(9);
                        }
                    });
                })
                .is_err()
            {
                stage_done.set(9);
            }
        })
        .map_err(show)
        .t()?;
    let finished = drive_two(
        &mut ring,
        &mut server,
        &mut client,
        || stage.get() == 3 || stage.get() == 9,
        Duration::from_secs(3),
    )
    .t()?;
    check(finished && stage.get() == 3, "auth fetch audit chain")
}

#[test]
fn e2e_04_deferred_responder_waits_for_upstream() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let inbound_gate = Gate::new(GateMode::Echo);
    let held = inbound_gate.held();
    let mut inbound = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        inbound_gate,
    )
    .t()?;
    let inbound_port = inbound.local_addr().port();
    let mut upstream = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(4).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let upstream_port = upstream.local_addr().port();
    let mut caller = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let slot = Slot::new();
    let done = slot.clone();
    let request = Request::get(&format!("http://127.0.0.1:{inbound_port}/hold"))
        .map_err(show)
        .t()?;
    caller
        .submit(&mut ring, request, move |_ctx, _id, result| {
            done.set(result)
        })
        .map_err(show)
        .t()?;
    let parked = drive_until(
        &mut ring,
        |ring| {
            inbound.drive(ring)?;
            upstream.drive(ring)?;
            caller.drive_with(
                ring,
                &mut nexora::CompletionRoutes::new(&mut inbound, &mut upstream),
            )?;
            Ok(held.borrow().is_some())
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(parked, "responder was not parked").t()?;
    let upstream_slot = Slot::new();
    let upstream_done = upstream_slot.clone();
    let upstream_request = Request::post(
        &format!("http://127.0.0.1:{upstream_port}/echo"),
        Bytes::copy_from_slice(b"up"),
    )
    .map_err(show)
    .t()?;
    let held_reply = Rc::clone(&held);
    caller
        .submit(&mut ring, upstream_request, move |_ctx, _id, result| {
            upstream_done.set(result.is_ok());
            if let Ok(response) = result
                && let Some(responder) = held_reply.borrow_mut().take()
                && responder.respond(response).is_err()
            {
                upstream_done.set(false);
            }
        })
        .map_err(show)
        .t()?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            inbound.drive(ring)?;
            upstream.drive(ring)?;
            caller.drive_with(
                ring,
                &mut nexora::CompletionRoutes::new(&mut inbound, &mut upstream),
            )?;
            Ok(slot.calls() > 0)
        },
        Duration::from_secs(3),
    )
    .t()?;
    check(finished, "gateway timed out").t()?;
    check(
        body_of(&slot).t()?.as_slice() == b"up",
        "upstream body reached the caller",
    )
    .t()?;
    check(upstream_slot.calls() == 1, "upstream callback once")
}

#[test]
fn e2e_05_websocket_text_binary_and_proactive_send() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let echo = WebSocketEcho::new();
    let texts = echo.texts();
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?
    .with_websocket_handler("/stream", echo);
    let port = server.local_addr().port();
    let mut client = WebSocketClient::new(&mut ring, websocket_config(1, 2).t()?).t()?;
    let opened = Slot::new();
    let opened_done = opened.clone();
    let url = format!("ws://127.0.0.1:{port}/stream");
    let session = client
        .connect(&mut ring, &url, Headers::new(), move |_ctx, id, result| {
            opened_done.set(result.map(|()| id).map_err(show));
        })
        .map_err(show)
        .t()?;
    let received = Rc::new(RefCell::new(Vec::new()));
    let received_handler = Rc::clone(&received);
    client
        .set_message_handler(session, move |ctx, socket, event| {
            if let WebSocketEvent::Text(text) = event {
                received_handler.borrow_mut().push(text.clone());
                socket.send_text(ctx, text);
            }
        })
        .map_err(show)
        .t()?;
    let connected = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(opened.calls() > 0 && client.is_open(session))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(connected, "websocket upgrade timed out").t()?;
    client
        .send_text(&mut ring, session, "hello")
        .map_err(show)
        .t()?;
    client
        .send_binary(&mut ring, session, Bytes::copy_from_slice(&[9u8; 64]))
        .map_err(show)
        .t()?;
    let echoed = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(texts.borrow().iter().any(|text| text == "hello"))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(echoed, "server did not observe the text").t()?;
    let id = WebSocketSessionId::new(session.raw());
    server
        .websocket_send(id, WebSocketMessage::Text(String::from("push")))
        .map_err(show)
        .t()?;
    let pushed = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(received.borrow().iter().any(|text| text == "push"))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(pushed, "proactive server send").t()?;

    let identity = localhost_identity(&[AlpnProtocol::Http11]).t()?;
    let mut tls_config = server_config(6).t()?;
    tls_config.tls = Some(identity.server);
    let mut tls_server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        tls_config,
        Gate::new(GateMode::Echo),
    )
    .t()?
    .with_websocket_handler("/stream", WebSocketEcho::new());
    let tls_port = tls_server.local_addr().port();
    let mut wss_config = websocket_config(4, 5).t()?;
    wss_config.tls_config = Some(identity.client);
    let mut wss = WebSocketClient::new(&mut ring, wss_config).t()?;
    wss.resolve_host("localhost", tls_port, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let wss_open = Slot::new();
    let wss_url = format!("wss://localhost:{tls_port}/stream");
    let wss_session = wss
        .connect(
            &mut ring,
            &wss_url,
            Headers::new(),
            move |_ctx, id, result| {
                wss_open.set(result.map(|()| id.raw()).map_err(show));
            },
        )
        .map_err(show)
        .t()?;
    let secure = drive_until(
        &mut ring,
        |ring| {
            tls_server.drive(ring)?;
            wss.drive_with(ring, &mut tls_server)?;
            Ok(wss.is_open(wss_session))
        },
        Duration::from_secs(3),
    )
    .t()?;
    check(secure, "wss upgrade")
}

#[test]
fn e2e_06_custom_ca_and_mock_dns() -> TestResult {
    let _exclusive = support::exclusive();
    let dns = MockDns::spawn(DnsPlan::answer(vec![Ipv4Addr::LOCALHOST]))
        .map_err(show)
        .t()?;
    let identity = localhost_identity(&[AlpnProtocol::Http11]).t()?;
    let mut ring = proactor().t()?;
    let mut tls_config = server_config(3).t()?;
    tls_config.tls = Some(identity.server);
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        tls_config,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let port = server.local_addr().port();
    let mut config = client_config(1, 2).t()?;
    config.tls_config = Some(identity.client);
    config.dns_servers_csv = Some(dns.servers_csv());
    let mut client = HttpClient::new(&mut ring, config).t()?;
    client.resolve_host("localhost", port, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let pinned = Slot::new();
    let pinned_done = pinned.clone();
    let pinned_request = Request::get(&format!("https://localhost:{port}/echo"))
        .map_err(show)
        .t()?;
    client
        .submit(&mut ring, pinned_request, move |_ctx, _id, result| {
            pinned_done.set(result);
        })
        .map_err(show)
        .t()?;
    let pinned_ready = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(pinned.calls() > 0)
        },
        Duration::from_secs(3),
    )
    .t()?;
    check(pinned_ready, "pinned https timed out").t()?;
    check(body_of(&pinned).t()?.as_slice() == b"ok", "pinned https").t()?;
    check(dns.udp_queries() == 0, "pinned localhost skipped mock dns").t()?;
    let mut clear = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(7).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let clear_port = clear.local_addr().port();
    let mut named_config = client_config(4, 5).t()?;
    named_config.dns_servers_csv = Some(dns.servers_csv());
    let mut named_client = HttpClient::new(&mut ring, named_config).t()?;
    let named = Slot::new();
    let named_done = named.clone();
    let named_request = Request::get(&format!("http://live.test:{clear_port}/echo"))
        .map_err(show)
        .t()?;
    named_client
        .submit(&mut ring, named_request, move |_ctx, _id, result| {
            named_done.set(result);
        })
        .map_err(show)
        .t()?;
    let named_ready = drive_until(
        &mut ring,
        |ring| {
            clear.drive(ring)?;
            named_client.drive_with(ring, &mut clear)?;
            Ok(named.calls() > 0)
        },
        Duration::from_secs(4),
    )
    .t()?;
    check(named_ready, "named cleartext exchange timed out").t()?;
    check(dns.udp_queries() >= 1, "named host queried mock dns").t()?;
    check(body_of(&named).t()?.as_slice() == b"ok", "named echo body")
}

#[test]
fn e2e_07_one_port_serves_http1_http2_and_websocket() -> TestResult {
    let _exclusive = support::exclusive();
    let threads = support::thread_count().map_err(show).t()?;
    let mut ring = proactor().t()?;
    let echo = WebSocketEcho::new();
    let texts = echo.texts();
    let config = server_config(3).t()?;
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        config,
        Gate::new(GateMode::Echo),
    )
    .t()?
    .with_websocket_handler("/stream", echo);
    let port = server.local_addr().port();
    let mut http1 = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let http_slot = Slot::new();
    let http_done = http_slot.clone();
    http1
        .submit(
            &mut ring,
            Request::get(&format!("http://127.0.0.1:{port}/echo"))
                .map_err(show)
                .t()?,
            move |_ctx, _id, result| http_done.set(result.is_ok()),
        )
        .map_err(show)
        .t()?;
    check(
        drive_until(
            &mut ring,
            |ring| {
                server.drive(ring)?;
                http1.drive_with(ring, &mut server)?;
                Ok(http_slot.calls() > 0)
            },
            Duration::from_secs(2),
        )
        .t()?,
        "http/1 on the shared port timed out",
    )
    .t()?;
    check(http_slot.take() == Some(true), "http/1 echo").t()?;
    http1.shutdown_with(&mut ring, &mut server).t()?;
    drop(http1);
    let mut http2_config = client_config(4, 5).t()?;
    http2_config.http2_prior_knowledge = true;
    http2_config.prefer_http2 = true;
    let mut http2 = HttpClient::new(&mut ring, http2_config).t()?;
    let http2_slot = Slot::new();
    let http2_done = http2_slot.clone();
    http2
        .submit(
            &mut ring,
            Request::get(&format!("http://127.0.0.1:{port}/echo"))
                .map_err(show)
                .t()?,
            move |_ctx, _id, result| http2_done.set(result.is_ok()),
        )
        .map_err(show)
        .t()?;
    check(
        drive_until(
            &mut ring,
            |ring| {
                server.drive(ring)?;
                http2.drive_with(ring, &mut server)?;
                Ok(http2_slot.calls() > 0)
            },
            Duration::from_secs(2),
        )
        .t()?,
        "http/2 on the shared port timed out",
    )
    .t()?;
    check(http2_slot.take() == Some(true), "http/2 echo").t()?;
    http2.shutdown_with(&mut ring, &mut server).t()?;
    drop(http2);
    let mut websocket = WebSocketClient::new(&mut ring, websocket_config(6, 7).t()?).t()?;
    let session = websocket
        .connect(
            &mut ring,
            &format!("ws://127.0.0.1:{port}/stream"),
            Headers::new(),
            |_ctx, _id, _result| {},
        )
        .map_err(show)
        .t()?;
    let opened = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            websocket.drive_with(ring, &mut server)?;
            Ok(websocket.is_open(session))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(opened, "websocket on the shared port timed out").t()?;
    websocket
        .send_text(&mut ring, session, "subscribe")
        .map_err(show)
        .t()?;
    let echoed = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            websocket.drive_with(ring, &mut server)?;
            Ok(texts.borrow().iter().any(|text| text == "subscribe"))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(echoed, "websocket echo on the shared port").t()?;
    check(
        support::thread_count().map_err(show).t()? == threads,
        "thread count stayed at the baseline",
    )
}
