mod support;

use std::{
    cell::{Cell, RefCell},
    net::Ipv4Addr,
    rc::Rc,
    time::Duration,
};

use nexora::{
    Error, Headers, HttpClient, HttpServer, OriginKey, Request, WebSocketClient,
    WebSocketCloseCode, WebSocketCloseFrame, proto::Scheme,
};
use support::{
    DnsPlan, Gate, GateMode, IntoCheck, MockDns, Slot, TestResult, WebSocketEcho, check,
    client_config, drive_until, proactor, server_config, websocket_config,
};

fn url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

fn spin(
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

#[test]
fn lc_01_cancel_across_request_phases() -> TestResult {
    let _exclusive = support::exclusive();
    let dns = MockDns::spawn(
        DnsPlan::answer(vec![Ipv4Addr::LOCALHOST]).delay(Duration::from_millis(350)),
    )
    .t()?;
    let mut ring = proactor().t()?;
    let gate = Gate::new(GateMode::Echo);
    let held = gate.held();
    let mut server =
        HttpServer::bind(&mut ring, support::ephemeral(), server_config(3).t()?, gate).t()?;
    let port = server.local_addr().port();
    let mut config = client_config(1, 2).t()?;
    config.dns_servers_csv = Some(dns.servers_csv());
    let mut client = HttpClient::new(&mut ring, config).t()?;
    let outcomes = Rc::new(RefCell::new(Vec::new()));
    let mut ids = Vec::new();
    for index in 0..4 {
        let outcomes = Rc::clone(&outcomes);
        let request = Request::get(&format!("http://wait.test:{port}/echo")).t()?;
        let id = client
            .submit(&mut ring, request, move |_ctx, id, result| {
                outcomes.borrow_mut().push((id.raw(), result.is_err()));
            })
            .t()?;
        ids.push((index, id));
    }
    let started = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(dns.udp_queries() > 0)
        },
        Duration::from_millis(200),
    )
    .t()?;
    check(started, "dns query did not start").t()?;
    check(client.cancel(&mut ring, ids[0].1), "first waiter cancels").t()?;
    check(
        !client.cancel(&mut ring, ids[0].1),
        "second cancel is terminal",
    )
    .t()?;
    let done = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(outcomes.borrow().len() == 4)
        },
        Duration::from_secs(3),
    )
    .t()?;
    check(done, "dns waiters did not finish").t()?;
    let cancelled = outcomes
        .borrow()
        .iter()
        .filter(|(id, failed)| *id == ids[0].1.raw() && *failed)
        .count();
    check(cancelled == 1, "cancelled waiter fires once").t()?;
    check(
        outcomes
            .borrow()
            .iter()
            .filter(|(_, failed)| !failed)
            .count()
            == 3,
        "the other dns waiters complete",
    )
    .t()?;

    client.shutdown_with(&mut ring, &mut server).t()?;
    let mut config = client_config(4, 5).t()?;
    config.dns_servers_csv = Some(dns.servers_csv());
    config.pool.max_connections_per_origin = 1;
    let mut limited = HttpClient::new(&mut ring, config).t()?;
    let queued = Rc::new(Cell::new(0u32));
    let hold_queued = Rc::clone(&queued);
    limited
        .submit(
            &mut ring,
            Request::get(&url(port, "/hold")).t()?,
            move |_ctx, _id, result| {
                if matches!(result, Err(Error::Cancelled)) {
                    hold_queued.set(hold_queued.get().saturating_add(1));
                } else {
                    hold_queued.set(hold_queued.get().saturating_add(10));
                }
            },
        )
        .t()?;
    let parked = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            limited.drive_with(ring, &mut server)?;
            Ok(held.borrow().is_some())
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(parked, "active exchange was not held").t()?;
    let echo_queued = Rc::clone(&queued);
    let echo_id = limited
        .submit(
            &mut ring,
            Request::get(&url(port, "/echo")).t()?,
            move |_ctx, _id, result| {
                if matches!(result, Err(Error::Cancelled)) {
                    echo_queued.set(echo_queued.get().saturating_add(1));
                } else {
                    echo_queued.set(echo_queued.get().saturating_add(10));
                }
            },
        )
        .t()?;
    check(limited.cancel(&mut ring, echo_id), "queued request cancels").t()?;
    let settled = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            limited.drive_with(ring, &mut server)?;
            Ok(queued.get() > 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(settled && queued.get() == 1, "queued cancel callback once").t()?;
    if let Some(responder) = held.borrow_mut().take() {
        responder
            .respond(nexora::Response::text(nexora::StatusCode::OK, "late"))
            .t()?;
    }
    client.shutdown_with(&mut ring, &mut server).t()?;
    drop(client);
    limited.shutdown_with(&mut ring, &mut server).t()?;
    let mut last_config = client_config(6, 7).t()?;
    last_config.dns_servers_csv = Some(dns.servers_csv());
    let mut last = HttpClient::new(&mut ring, last_config).t()?;
    let last_hits = Rc::new(Cell::new(0u32));
    let mut last_ids = Vec::new();
    let baseline = dns.udp_queries();
    for _ in 0..2 {
        let last_hits = Rc::clone(&last_hits);
        let id = last
            .submit(
                &mut ring,
                Request::get(&format!("http://wait.test:{port}/echo")).t()?,
                move |_ctx, _id, result| {
                    if matches!(result, Err(Error::Cancelled)) {
                        last_hits.set(last_hits.get().saturating_add(1));
                    } else {
                        last_hits.set(last_hits.get().saturating_add(10));
                    }
                },
            )
            .t()?;
        last_ids.push(id);
    }
    let sent = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            last.drive_with(ring, &mut server)?;
            Ok(dns.udp_queries() > baseline)
        },
        Duration::from_millis(400),
    )
    .t()?;
    check(sent, "shared dns query was not sent").t()?;
    check(
        last.cancel(&mut ring, last_ids[0]),
        "first of the pair cancels",
    )
    .t()?;
    check(last.cancel(&mut ring, last_ids[1]), "last waiter cancels").t()?;
    let both = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            last.drive_with(ring, &mut server)?;
            Ok(last_hits.get() >= 2)
        },
        Duration::from_millis(400),
    )
    .t()?;
    check(both && last_hits.get() == 2, "each waiter fires once").t()?;
    let held_queries = dns.udp_queries();
    let released = Rc::new(Cell::new(false));
    let released_done = Rc::clone(&released);
    last.submit(
        &mut ring,
        Request::get(&format!("http://wait.test:{port}/echo")).t()?,
        move |_ctx, _id, result| released_done.set(result.is_ok()),
    )
    .t()?;
    let retried = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            last.drive_with(ring, &mut server)?;
            Ok(dns.udp_queries() > held_queries)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(retried, "last waiter cancel did not release the query").t()?;
    drop(server);
    Ok(())
}

#[test]
fn lc_02_cancel_followup_retirement() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let gate = Gate::new(GateMode::Echo);
    let held = gate.held();
    let mut server =
        HttpServer::bind(&mut ring, support::ephemeral(), server_config(3).t()?, gate).t()?;
    let port = server.local_addr().port();
    let mut client = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let slot = Slot::new();
    let done = slot.clone();
    let id = client
        .submit(
            &mut ring,
            Request::get(&url(port, "/hold")).t()?,
            move |_ctx, _id, result| done.set(matches!(result, Err(Error::Cancelled))),
        )
        .t()?;
    let parked = spin(
        &mut ring,
        &mut server,
        &mut client,
        || held.borrow().is_some(),
        Duration::from_secs(2),
    )
    .t()?;
    check(parked, "in-flight request was not accepted").t()?;
    check(client.cancel(&mut ring, id), "in-flight cancel").t()?;
    let cancelled = spin(
        &mut ring,
        &mut server,
        &mut client,
        || slot.calls() == 1,
        Duration::from_secs(2),
    )
    .t()?;
    check(
        cancelled && slot.take() == Some(true),
        "cancel callback once",
    )
    .t()?;
    let follow = Slot::new();
    let follow_done = follow.clone();
    client
        .submit(
            &mut ring,
            Request::get(&url(port, "/echo")).t()?,
            move |_ctx, _id, result| follow_done.set(result.is_ok()),
        )
        .t()?;
    let recovered = spin(
        &mut ring,
        &mut server,
        &mut client,
        || follow.calls() == 1,
        Duration::from_secs(2),
    )
    .t()?;
    check(
        recovered && follow.take() == Some(true),
        "follow-up succeeds",
    )
    .t()?;
    ring.shutdown().t()
}

#[test]
fn lc_03_responder_drop_disconnect() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let gate = Gate::new(GateMode::Echo);
    let held = gate.held();
    let mut server =
        HttpServer::bind(&mut ring, support::ephemeral(), server_config(3).t()?, gate).t()?;
    let port = server.local_addr().port();
    let mut client = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let dropped = Slot::new();
    let dropped_done = dropped.clone();
    client
        .submit(
            &mut ring,
            Request::get(&url(port, "/drop")).t()?,
            move |_ctx, _id, result| {
                dropped_done.set(result.map(|response| response.status.as_u16()).t());
            },
        )
        .t()?;
    let saw_drop = spin(
        &mut ring,
        &mut server,
        &mut client,
        || dropped.calls() == 1,
        Duration::from_secs(2),
    )
    .t()?;
    check(saw_drop, "drop responder timed out").t()?;
    check(
        dropped
            .take()
            .ok_or_else(|| String::from("missing drop"))
            .t()?
            == Ok(500),
        "dropped responder becomes 500",
    )
    .t()?;
    let late = Slot::new();
    let late_done = late.clone();
    let id = client
        .submit(
            &mut ring,
            Request::get(&url(port, "/hold")).t()?,
            move |_ctx, _id, result| late_done.set(matches!(result, Err(Error::Cancelled))),
        )
        .t()?;
    let parked = spin(
        &mut ring,
        &mut server,
        &mut client,
        || held.borrow().is_some(),
        Duration::from_secs(2),
    )
    .t()?;
    check(parked, "responder was not parked").t()?;
    check(client.cancel(&mut ring, id), "disconnect the caller").t()?;
    let saw_close = spin(
        &mut ring,
        &mut server,
        &mut client,
        || {
            held.borrow()
                .as_ref()
                .is_some_and(nexora::Responder::is_closed)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(saw_close, "server did not observe the disconnect").t()?;
    let responder = held
        .borrow_mut()
        .take()
        .ok_or_else(|| String::from("missing responder"))
        .t()?;
    let respond_error = responder.respond(nexora::Response::text(nexora::StatusCode::OK, "late"));
    check(respond_error.is_err(), "respond after disconnect fails").t()?;
    let observed = spin(
        &mut ring,
        &mut server,
        &mut client,
        || late.calls() == 1,
        Duration::from_secs(2),
    )
    .t()?;
    check(
        observed && late.take() == Some(true),
        "caller observes cancellation",
    )
}

#[test]
fn lc_04_goaway_close_eviction() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let mut config = client_config(1, 2).t()?;
    config.pool.idle_timeout = Duration::from_millis(40);
    config.pool.max_idle_per_origin = 1;
    let gate = Gate::new(GateMode::Echo);
    let held = gate.held();
    let mut server =
        HttpServer::bind(&mut ring, support::ephemeral(), server_config(3).t()?, gate).t()?;
    let port = server.local_addr().port();
    let mut client = HttpClient::new(&mut ring, config).t()?;
    let slot = Slot::new();
    let done = slot.clone();
    client
        .submit(
            &mut ring,
            Request::get(&url(port, "/echo")).t()?,
            move |_ctx, _id, result| done.set(result.is_ok()),
        )
        .t()?;
    let ok = spin(
        &mut ring,
        &mut server,
        &mut client,
        || slot.calls() == 1,
        Duration::from_secs(2),
    )
    .t()?;
    check(ok, "warmup request").t()?;
    let origin = OriginKey::new(Scheme::Http, "127.0.0.1", port);
    let evicted = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            client.drive_with(ring, &mut server)?;
            Ok(client.idle_connection_count(&origin) == 0)
        },
        Duration::from_secs(1),
    )
    .t()?;
    check(evicted, "idle connection was not evicted").t()?;
    client.shutdown_with(&mut ring, &mut server).t()?;
    drop(client);
    let mut http2_config = client_config(7, 8).t()?;
    http2_config.http2_prior_knowledge = true;
    http2_config.prefer_http2 = true;
    let mut http2 = HttpClient::new(&mut ring, http2_config).t()?;
    let primed = Slot::new();
    let primed_done = primed.clone();
    http2
        .submit(
            &mut ring,
            Request::get(&url(port, "/hold")).t()?,
            move |_ctx, _id, result| primed_done.set(result.is_ok()),
        )
        .t()?;
    let parked = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            http2.drive_with(ring, &mut server)?;
            Ok(held.borrow().is_some())
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(parked, "http2 exchange was not held").t()?;
    server.initiate_graceful_shutdown(&mut ring).t()?;
    let responder = held
        .borrow_mut()
        .take()
        .ok_or_else(|| String::from("missing goaway responder"))
        .t()?;
    responder
        .respond(nexora::Response::text(nexora::StatusCode::OK, "late"))
        .t()?;
    let migrated = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            http2.drive_with(ring, &mut server)?;
            Ok(primed.calls() == 1)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(
        migrated && primed.take() == Some(true),
        "in-flight request survived goaway",
    )
    .t()?;
    http2.shutdown_with(&mut ring, &mut server).t()?;
    drop(http2);

    let echo = WebSocketEcho::new();
    let mut websocket_server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(6).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?
    .with_websocket_handler("/stream", echo);
    let websocket_port = websocket_server.local_addr().port();
    let mut websocket = WebSocketClient::new(&mut ring, websocket_config(4, 5).t()?).t()?;
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    let session = websocket
        .connect(
            &mut ring,
            &format!("ws://127.0.0.1:{websocket_port}/stream"),
            Headers::new(),
            move |_ctx, _id, result| {
                if result.is_ok() {
                    recorded.borrow_mut().push(1u8);
                }
            },
        )
        .t()?;
    let opened = drive_until(
        &mut ring,
        |ring| {
            websocket_server.drive(ring)?;
            websocket.drive_with(
                ring,
                &mut nexora::CompletionRoutes::new(&mut websocket_server, &mut server),
            )?;
            Ok(events.borrow().contains(&1))
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(opened, "websocket did not open").t()?;
    websocket
        .close(
            &mut ring,
            session,
            Some(WebSocketCloseFrame {
                code: WebSocketCloseCode::Normal,
                reason: "done".into(),
            }),
        )
        .t()?;
    let closed = drive_until(
        &mut ring,
        |ring| {
            websocket_server.drive(ring)?;
            websocket.drive_with(
                ring,
                &mut nexora::CompletionRoutes::new(&mut websocket_server, &mut server),
            )?;
            Ok(!websocket.is_open(session) && websocket.active_session_count() == 0)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(closed, "websocket close was not observed")
}

#[test]
fn lc_05_sibling_survives_client_drop() -> TestResult {
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
    let mut doomed = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let fired = Rc::new(Cell::new(false));
    let flag = Rc::clone(&fired);
    doomed
        .submit(
            &mut ring,
            Request::get(&url(port, "/hold")).t()?,
            move |_ctx, _id, _result| flag.set(true),
        )
        .t()?;
    let _ = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            doomed.drive_with(ring, &mut server)?;
            Ok(false)
        },
        Duration::from_millis(30),
    )
    .t()?;
    drop(doomed);
    let mut sibling = HttpClient::new(&mut ring, client_config(4, 5).t()?).t()?;
    let slot = Slot::new();
    let done = slot.clone();
    sibling
        .submit(
            &mut ring,
            Request::get(&url(port, "/echo")).t()?,
            move |_ctx, _id, result| done.set(result.is_ok()),
        )
        .t()?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            server.drive(ring)?;
            sibling.drive_with(ring, &mut |completion: nexora::Completion,
                                            submissions: &mut nexora::SubmissionContext<
                '_,
            >| {
                if [1, 2].contains(&completion.operation_id.subsystem_id().raw()) {
                    // The dropped owner retains its DMA operands and suppresses callbacks.
                    submissions.claim_completion(completion)
                } else {
                    nexora::CompletionDispatcher::dispatch(&mut server, completion, submissions)
                }
            })?;
            Ok(slot.calls() == 1)
        },
        Duration::from_secs(2),
    )
    .t()?;
    check(
        finished && slot.take() == Some(true),
        "sibling client completes",
    )
    .t()?;
    check(!fired.get(), "dropped client callback stays silent").t()?;
    ring.shutdown().t()
}

#[test]
fn lc_06_request_cancel_descriptor_balance() -> TestResult {
    let _exclusive = support::exclusive();
    let before_fd = support::open_fd_count().t()?;
    let before_threads = support::thread_count().t()?;
    let after_echo;
    {
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
        let mut steady = 0usize;
        for index in 0..1000 {
            let slot = Slot::new();
            let done = slot.clone();
            client
                .submit(
                    &mut ring,
                    Request::get(&url(port, "/echo")).t()?,
                    move |_ctx, _id, result| done.set(result.is_ok()),
                )
                .map_err(|error| format!("echo submit {index}: {error}"))?;
            let ok = spin(
                &mut ring,
                &mut server,
                &mut client,
                || slot.calls() == 1,
                Duration::from_secs(2),
            )
            .map_err(|error| format!("echo drive {index}: {error}"))?;
            check(
                ok && slot.take() == Some(true),
                format!("request failed inside the leak loop at {index}"),
            )?;
            if index == 0 {
                steady = support::open_fd_count().t()?;
            }
        }
        after_echo = support::open_fd_count().t()?;
        check(
            after_echo == steady,
            format!("echo cycle grew descriptors: steady {steady} after {after_echo}"),
        )?;
        for index in 0..100 {
            let slot = Slot::new();
            let done = slot.clone();
            let id = client
                .submit(
                    &mut ring,
                    Request::get(&url(port, "/hold")).t()?,
                    move |_ctx, _id, result| done.set(matches!(result, Err(Error::Cancelled))),
                )
                .map_err(|error| format!("cancel submit {index}: {error}"))?;
            check(client.cancel(&mut ring, id), format!("cancel {index}"))?;
            let ok = spin(
                &mut ring,
                &mut server,
                &mut client,
                || slot.calls() == 1,
                Duration::from_secs(2),
            )
            .map_err(|error| format!("cancel drive {index}: {error}"))?;
            check(ok, format!("cancel callback missing at {index}"))?;
        }
        let _settled = drive_until(
            &mut ring,
            |ring| {
                server.drive(ring)?;
                client.drive_with(ring, &mut server)?;
                Ok(false)
            },
            Duration::from_millis(50),
        )
        .map_err(|error| format!("cancel settle: {error}"))?;
        let after_cancel = support::open_fd_count().t()?;
        check(
            after_cancel <= after_echo,
            format!("cancel cycle grew descriptors: echo {after_echo} cancel {after_cancel}"),
        )?;
        check(
            support::thread_count().t()? == before_threads,
            "thread count grew",
        )?;
        client.shutdown_with(&mut ring, &mut server).t()?;
        drop(client);
        drop(server);
    }
    let after_fd = support::open_fd_count().t()?;
    check(
        after_fd <= after_echo,
        format!("drop grew descriptors: live {after_echo} dropped {after_fd} baseline {before_fd}"),
    )
}

#[test]
fn lc_callback_followup_submission() -> TestResult {
    let _exclusive = support::exclusive();
    let mut ring = proactor().t()?;
    let mut client = HttpClient::new(&mut ring, client_config(1, 2).t()?).t()?;
    let idle_enters = ring.stats().enter_calls;
    check(client.drive(&mut ring).t()? == 0, "idle drive has no CQEs")?;
    check(
        ring.stats().enter_calls == idle_enters,
        "idle drive entered the kernel",
    )?;
    let calls = Rc::new(Cell::new(0));
    let callback = Rc::clone(&calls);
    client
        .set_timer(&mut ring, Duration::ZERO, move |ctx, _| {
            callback.set(callback.get() + 1);
            let next = Rc::clone(&callback);
            ctx.set_timer(Duration::ZERO, move |_, _| next.set(next.get() + 1));
        })
        .t()?;
    ring.submit().t()?;
    // SAFETY: The open ring is exclusively borrowed for this synchronous wait.
    // Leaving the CQE queued makes the next SDK drive the sole callback dispatcher.
    unsafe { (&*ring.ring_mut()).submitter().submit_and_wait(1) }.t()?;
    let enters = ring.stats().enter_calls;
    check(client.drive(&mut ring).t()? == 1, "one initial timer CQE")?;
    check(
        calls.get() == 1,
        "follow-up callback must await another turn",
    )?;
    check(
        ring.stats().enter_calls > enters,
        "follow-up entered this turn",
    )?;
    check(ring.submit().t()? == 0, "follow-up was already published")?;
    let finished = drive_until(
        &mut ring,
        |ring| {
            client.drive(ring)?;
            Ok(calls.get() == 2)
        },
        Duration::from_secs(1),
    )
    .t()?;
    check(finished, "follow-up timer must complete")?;
    client.shutdown(&mut ring);
    ring.shutdown().t()
}
