mod support;

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use nexora::{AlpnProtocol, Bytes, HttpClient, HttpServer, Request};
use support::{Gate, GateMode, IntoCheck, Slot, TestResult, check};

#[test]
fn e2e_scenario_missing_alpn_rejects_post_unless_http11_is_allowed() -> TestResult {
    let _exclusive = support::exclusive();
    for protocols in [
        vec![AlpnProtocol::Http2],
        vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
        vec![AlpnProtocol::Http11],
        vec![],
    ] {
        let allowed = protocols.contains(&AlpnProtocol::Http11);
        let identity = support::localhost_identity(&[]).t()?;
        let mut ring = support::proactor().t()?;
        let gate = Gate::new(GateMode::Echo);
        let hits = gate.hits();
        let mut server_config = support::server_config(3).t()?;
        server_config.tls = Some(identity.server);
        let mut server =
            HttpServer::bind(&mut ring, support::ephemeral(), server_config, gate).t()?;
        let port = server.local_addr().port();
        let mut config = support::client_config(1, 2).t()?;
        config.prefer_http2 = true;
        config.tls_config = Some(identity.client.with_alpn(&protocols));
        let mut client = HttpClient::new(&mut ring, config).t()?;
        client.resolve_host("localhost", port, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let result = Slot::new();
        let completion = result.clone();
        let request = Request::post(
            &format!("https://localhost:{port}/echo"),
            Bytes::from_static(b"non-idempotent-post"),
        )
        .t()?;
        client
            .submit(&mut ring, request, move |_, _, outcome| {
                completion.set(outcome)
            })
            .t()?;
        check(
            support::drive_until(
                &mut ring,
                |ring| {
                    server.drive(ring)?;
                    client.drive_with(ring, &mut server)?;
                    Ok(result.calls() != 0)
                },
                Duration::from_secs(2),
            )
            .t()?,
            "missing ALPN did not settle the request",
        )?;
        let outcome = result
            .take()
            .ok_or_else(|| String::from("missing terminal result"))?;
        if allowed {
            let response = outcome.t()?;
            check(
                response.body.as_slice() == b"non-idempotent-post",
                "HTTP/1.1 fallback response",
            )?;
            check(hits.get() == 1, "allowed POST must reach the server once")?;
        } else {
            check(
                matches!(outcome, Err(nexora::Error::Proto(nexora::proto::ProtoError::Tls(ref message)))
                    if message == "peer did not negotiate HTTP/2 ALPN"),
                "missing ALPN must report the explicit TLS policy failure",
            )?;
            check(hits.get() == 0, "forbidden POST reached the server")?;
        }
        client.shutdown_with(&mut ring, &mut server).t()?;
        server.drive(&mut ring).t()?;
        check(
            result.calls() == 1,
            "ALPN outcome must complete exactly once",
        )?;
        check(
            hits.get() == u32::from(allowed),
            "shutdown dispatched a forbidden POST",
        )?;
    }
    Ok(())
}
