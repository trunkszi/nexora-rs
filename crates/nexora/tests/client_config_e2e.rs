//! Real loopback request/response limits and TLS identity separation.
//! The SNI probe replaces only the server handshake with a ClientHello parser.

mod support;

use std::{
    cell::RefCell,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, TcpListener},
    rc::Rc,
    time::Duration,
};

use nexora::{
    AlpnProtocol, Bytes, Error, HttpClient, HttpServer, HttpService, Request, RequestContext,
    Responder, Response, Version, proto::ProtoError,
};
use support::{IntoCheck, Slot, TestResult, check};

struct Observe {
    requests: Rc<RefCell<Vec<Request>>>,
    response: Bytes,
}

impl Observe {
    fn new(response: Bytes) -> Self {
        Self {
            requests: Rc::new(RefCell::new(Vec::new())),
            response,
        }
    }
}

impl HttpService for Observe {
    fn call(
        &mut self,
        _: &mut RequestContext,
        request: Request,
        responder: Responder,
    ) -> nexora::Result<()> {
        self.requests.borrow_mut().push(request);
        responder.respond(Response::ok(self.response.clone()))
    }
}

#[test]
fn e2e_lifecycle_scenario_upload_and_response_limits_are_independent() -> TestResult {
    let _exclusive = support::exclusive();
    for protocol in [Version::Http11, Version::Http2] {
        for (receive_cap, upload_cap, response_length) in [
            (0, usize::MAX, 0),
            (0, usize::MAX, 1),
            (0, 64, 0),
            (0, 63, 0),
            (1, 64, 1),
        ] {
            let mut ring = support::proactor().t()?;
            let service = Observe::new(Bytes::copy_from_slice(&vec![b'r'; response_length]));
            let observed = Rc::clone(&service.requests);
            let mut server = HttpServer::bind(
                &mut ring,
                support::ephemeral(),
                support::server_config(3).t()?,
                service,
            )
            .t()?;
            let mut config = support::client_config(1, 2).t()?;
            config.http2_prior_knowledge = protocol == Version::Http2;
            config.max_body_size = receive_cap;
            config.max_request_body_size = upload_cap;
            let mut client = HttpClient::new(&mut ring, config).t()?;
            let result = Slot::new();
            let completion = result.clone();
            let body = Bytes::copy_from_slice(&[b'u'; 64]);
            let request = Request::post(
                &format!("http://127.0.0.1:{}/upload", server.local_addr().port()),
                body.clone(),
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
                "independent body limits did not settle",
            )?;
            let outcome = result.take().ok_or("missing limit result")?;
            if upload_cap < body.len() {
                check(
                    matches!(outcome, Err(Error::BodyTooLarge { size: 64, max: 63 })),
                    "upload cap error",
                )?;
                check(
                    observed.borrow().is_empty(),
                    "oversized upload reached the handler",
                )?;
            } else {
                let requests = observed.borrow();
                check(
                    requests.len() == 1,
                    "upload must reach the handler exactly once",
                )?;
                check(
                    requests[0].body == body,
                    "receive cap changed the uploaded body",
                )?;
                check(requests[0].version == protocol, "expected wire protocol")?;
                if response_length > receive_cap {
                    check(
                        matches!(outcome, Err(Error::BodyTooLarge { size: 1, max: 0 })),
                        "response cap error",
                    )?;
                } else {
                    check(
                        outcome.t()?.body.len() == response_length,
                        "response below the receive cap",
                    )?;
                }
            }
            client.shutdown_with(&mut ring, &mut server).t()?;
            server.drive(&mut ring).t()?;
            check(
                result.calls() == 1,
                "body-limit completion must be terminal",
            )?;
        }
    }
    Ok(())
}

#[test]
fn e2e_scenario_tls_name_override_preserves_http_authority_and_verification() -> TestResult {
    let _exclusive = support::exclusive();
    for protocol in [AlpnProtocol::Http11, AlpnProtocol::Http2] {
        for tls_name in [None, Some("localhost"), Some("wrong.invalid")] {
            let mut ring = support::proactor().t()?;
            let identity = support::localhost_identity(&[protocol]).t()?;
            let mut server_config = support::server_config(3).t()?;
            server_config.tls = Some(identity.server);
            let service = Observe::new(Bytes::from_static(b"accepted"));
            let observed = Rc::clone(&service.requests);
            let mut server =
                HttpServer::bind(&mut ring, support::ephemeral(), server_config, service).t()?;
            let port = server.local_addr().port();
            let mut config = support::client_config(1, 2).t()?;
            config.prefer_http2 = protocol == AlpnProtocol::Http2;
            config.tls_config = Some(identity.client);
            config.tls_server_name = tls_name.map(String::from);
            let mut client = HttpClient::new(&mut ring, config).t()?;
            client.resolve_host(
                "origin.invalid",
                port,
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            );
            let result = Slot::new();
            let completion = result.clone();
            let request = Request::get(&format!("https://origin.invalid:{port}/authority")).t()?;
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
                "TLS name override did not settle",
            )?;
            let outcome = result.take().ok_or("missing TLS result")?;
            if tls_name == Some("localhost") {
                check(
                    outcome.t()?.body.as_slice() == b"accepted",
                    "trusted override must succeed",
                )?;
                let requests = observed.borrow();
                check(
                    requests.len() == 1,
                    "one request after successful verification",
                )?;
                let request = &requests[0];
                let authority = format!("origin.invalid:{port}");
                check(
                    request.uri.authority() == authority,
                    "TLS name replaced HTTP authority",
                )?;
                if protocol == AlpnProtocol::Http11 {
                    check(
                        request.header("host") == Some(authority.as_str()),
                        "default Host must retain the URI authority",
                    )?;
                    check(request.version == Version::Http11, "HTTP/1.1 route")?;
                } else {
                    check(request.version == Version::Http2, "HTTP/2 :authority route")?;
                }
            } else {
                check(
                    matches!(outcome, Err(Error::Proto(ProtoError::Tls(_)))),
                    "hostname verification must reject mismatches",
                )?;
                check(
                    observed.borrow().is_empty(),
                    "unverified request reached the handler",
                )?;
            }
            client.shutdown_with(&mut ring, &mut server).t()?;
            server.drive(&mut ring).t()?;
            check(result.calls() == 1, "TLS name result must be terminal")?;
        }
    }
    Ok(())
}

#[test]
fn integration_scenario_tls_override_is_sent_as_client_hello_sni() -> TestResult {
    let _exclusive = support::exclusive();
    let listener = TcpListener::bind(support::ephemeral()).t()?;
    listener.set_nonblocking(true).t()?;
    let port = listener.local_addr().t()?.port();
    let mut ring = support::proactor().t()?;
    let mut config = support::client_config(1, 2).t()?;
    config.tls_server_name = Some(String::from("localhost"));
    let mut client = HttpClient::new(&mut ring, config).t()?;
    client.resolve_host(
        "origin.invalid",
        port,
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    );
    let result = Slot::new();
    let completion = result.clone();
    client
        .submit(
            &mut ring,
            Request::get(&format!("https://origin.invalid:{port}/sni")).t()?,
            move |_, _, outcome| completion.set(outcome),
        )
        .t()?;
    let mut peer = None;
    let mut acceptor = rustls::server::Acceptor::default();
    let mut seen = None;
    check(
        support::drive_until(
            &mut ring,
            |ring| {
                client.drive(ring)?;
                if peer.is_none() {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(true)?;
                            peer = Some(stream);
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                        Err(error) => return Err(Error::Io(error)),
                    }
                }
                let stream = peer
                    .as_mut()
                    .ok_or_else(|| Error::InvalidState(String::from("missing TLS peer")))?;
                match acceptor.read_tls(stream) {
                    Ok(_) => {}
                    Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                    Err(error) => return Err(Error::Io(error)),
                }
                match acceptor.accept() {
                    Ok(Some(accepted)) => {
                        seen = accepted.client_hello().server_name().map(String::from);
                        Ok(true)
                    }
                    Ok(None) => Ok(false),
                    Err((error, _)) => Err(Error::InvalidState(error.to_string())),
                }
            },
            Duration::from_secs(2),
        )
        .t()?,
        "ClientHello did not arrive",
    )?;
    check(
        seen.as_deref() == Some("localhost"),
        "SNI must use the configured TLS name",
    )?;
    client.shutdown(&mut ring);
    check(
        result.calls() == 1,
        "unfinished SNI probe must settle once on shutdown",
    )?;
    Ok(())
}
