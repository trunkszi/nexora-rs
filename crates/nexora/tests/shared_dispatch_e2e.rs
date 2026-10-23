//! Caller-owned DNS, two HTTP clients, server, and timers sharing one real ring.
mod support;

use std::{cell::Cell, net::Ipv4Addr, rc::Rc, time::Duration};

use nexora::{CompletionRoutes, Error, HttpClient, HttpServer, Request};
use support::{
    DnsPlan, Gate, GateMode, IntoCheck, MockDns, TestResult, check, client_config, drive_until,
    proactor, server_config,
};

#[test]
fn e2e_lifecycle_shared_dispatch_routes_dns_sockets_timers_and_peer_retirement() -> TestResult {
    let _exclusive = support::exclusive();
    let dns = MockDns::spawn(DnsPlan::answer(vec![Ipv4Addr::LOCALHOST])).t()?;
    let mut ring = proactor().t()?;
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let mut first_config = client_config(1, 2).t()?;
    first_config.dns_servers_csv = Some(dns.servers_csv());
    let mut second_config = client_config(4, 5).t()?;
    second_config.dns_servers_csv = Some(dns.servers_csv());
    let mut first = HttpClient::new(&mut ring, first_config).t()?;
    let mut second = HttpClient::new(&mut ring, second_config).t()?;
    let port = server.local_addr().port();
    let completed = Rc::new(Cell::new(0));
    let failed = Rc::new(Cell::new(0));
    for index in 0..24 {
        let client = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        let completed = Rc::clone(&completed);
        let failed = Rc::clone(&failed);
        client
            .submit(
                &mut ring,
                Request::get(&format!("http://shared.test:{port}/echo")).t()?,
                move |_, _, result| {
                    if result.is_ok_and(|response| response.body.as_slice() == b"ok") {
                        completed.set(completed.get() + 1);
                    } else {
                        failed.set(failed.get() + 1);
                    }
                },
            )
            .t()?;
    }
    let timer = Rc::new(Cell::new(false));
    let fired = Rc::clone(&timer);
    first
        .set_timer(&mut ring, Duration::from_millis(1), move |_, _| {
            fired.set(true)
        })
        .t()?;
    check(
        drive_until(
            &mut ring,
            |ring| {
                server.drive(ring)?;
                first.drive_with(ring, &mut CompletionRoutes::new(&mut second, &mut server))?;
                second.drive_with(ring, &mut CompletionRoutes::new(&mut first, &mut server))?;
                Ok(completed.get() == 24 && timer.get())
            },
            Duration::from_secs(3),
        )
        .t()?,
        "shared ring did not complete all routes",
    )
    .t()?;
    check(
        failed.get() == 0 && dns.udp_queries() >= 2,
        "both clients resolved and completed exactly once",
    )
    .t()?;
    first
        .shutdown_with(
            &mut ring,
            &mut CompletionRoutes::new(&mut second, &mut server),
        )
        .t()?;
    let peer = Rc::new(Cell::new(false));
    let done = Rc::clone(&peer);
    second
        .submit(
            &mut ring,
            Request::get(&format!("http://shared.test:{port}/echo")).t()?,
            move |_, _, result| done.set(result.is_ok()),
        )
        .t()?;
    check(
        drive_until(
            &mut ring,
            |ring| {
                server.drive(ring)?;
                second.drive_with(ring, &mut CompletionRoutes::new(&mut first, &mut server))?;
                Ok(peer.get())
            },
            Duration::from_secs(2),
        )
        .t()?,
        "peer ring closed during first-client retirement",
    )
    .t()?;
    second
        .shutdown_with(
            &mut ring,
            &mut CompletionRoutes::new(&mut first, &mut server),
        )
        .t()?;
    check(
        completed.get() == 24,
        "retirement repeated a terminal callback",
    )
}

#[test]
fn e2e_scenario_shutdown_retires_pending_dns_without_closing_peer_ring() -> TestResult {
    let _exclusive = support::exclusive();
    let dns =
        MockDns::spawn(DnsPlan::answer(vec![Ipv4Addr::LOCALHOST]).delay(Duration::from_secs(1)))
            .t()?;
    let mut ring = proactor().t()?;
    let mut server = HttpServer::bind(
        &mut ring,
        support::ephemeral(),
        server_config(3).t()?,
        Gate::new(GateMode::Echo),
    )
    .t()?;
    let port = server.local_addr().port();
    let mut config = client_config(1, 2).t()?;
    config.dns_servers_csv = Some(dns.servers_csv());
    let mut first = HttpClient::new(&mut ring, config).t()?;
    let mut peer = HttpClient::new(&mut ring, client_config(4, 5).t()?).t()?;
    let cancelled = Rc::new(Cell::new(0));
    let observed = Rc::clone(&cancelled);
    first
        .submit(
            &mut ring,
            Request::get(&format!("http://delayed.test:{port}/echo")).t()?,
            move |_, _, result| {
                observed.set(
                    observed.get()
                        + if matches!(result, Err(Error::Cancelled)) {
                            1
                        } else {
                            100
                        },
                );
            },
        )
        .t()?;
    check(
        drive_until(
            &mut ring,
            |ring| {
                server.drive(ring)?;
                first.drive_with(ring, &mut CompletionRoutes::new(&mut peer, &mut server))?;
                Ok(dns.udp_queries() > 0)
            },
            Duration::from_secs(1),
        )
        .t()?,
        "DNS poll did not become active",
    )
    .t()?;
    first
        .shutdown_with(
            &mut ring,
            &mut CompletionRoutes::new(&mut peer, &mut server),
        )
        .t()?;
    first
        .shutdown_with(
            &mut ring,
            &mut CompletionRoutes::new(&mut peer, &mut server),
        )
        .t()?;
    let done = Rc::new(Cell::new(false));
    let completed = Rc::clone(&done);
    peer.submit(
        &mut ring,
        Request::get(&format!("http://127.0.0.1:{port}/echo")).t()?,
        move |_, _, result| completed.set(result.is_ok()),
    )
    .t()?;
    check(
        drive_until(
            &mut ring,
            |ring| {
                server.drive(ring)?;
                peer.drive_with(ring, &mut CompletionRoutes::new(&mut first, &mut server))?;
                Ok(done.get())
            },
            Duration::from_secs(2),
        )
        .t()?,
        "DNS retirement interrupted a peer request",
    )
    .t()?;
    peer.shutdown_with(
        &mut ring,
        &mut CompletionRoutes::new(&mut first, &mut server),
    )
    .t()?;
    check(
        cancelled.get() == 1,
        "DNS cancellation callback must fire exactly once",
    )
}
