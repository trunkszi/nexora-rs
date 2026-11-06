//! TLS HTTP/2 multiplex on one connection, with one stream cancelled.
//!
//! The listener offers ALPN `h2` and `http/1.1`. The client trusts the
//! self-signed localhost certificate and offers only `h2`. One submitted
//! stream is cancelled before the ring is polled; the other three must
//! complete with the posted body.

use std::{
    cell::Cell,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use nexora::{
    AlpnProtocol, Bytes, ClientConfig, Error, HttpClient, HttpServer, HttpService, Proactor,
    Request, RequestContext, Responder, Response, ServerConfig, StatusCode, SubsystemId,
    TlsClientConfig, TlsServerConfig,
};

struct Echo;

impl HttpService for Echo {
    /// Returns the request body unchanged.
    ///
    /// # Errors
    /// Returns a responder error when the stream is already closed.
    ///
    /// # Panics
    /// This method does not panic.
    fn call(
        &mut self,
        _ctx: &mut RequestContext,
        req: Request,
        responder: Responder,
    ) -> nexora::Result<()> {
        responder.respond(Response::ok(req.body))
    }
}

fn main() -> nexora::Result<()> {
    let mut proactor = Proactor::builder().build()?;
    let (identity, der) =
        TlsServerConfig::self_signed_for_localhost(&[AlpnProtocol::Http2, AlpnProtocol::Http11])?;
    let server_config = ServerConfig {
        net_subsystem: SubsystemId::new_unchecked(3),
        tls: Some(identity),
        ..ServerConfig::default()
    };
    let mut server = HttpServer::bind(
        &mut proactor,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_config,
        Echo,
    )?;
    let port = server.local_addr().port();

    let client_config = ClientConfig {
        net_subsystem: SubsystemId::new_unchecked(1),
        dns_subsystem: SubsystemId::new_unchecked(2),
        prefer_http2: true,
        http2_prior_knowledge: false,
        tls_config: Some(TlsClientConfig::with_root_certificates(
            &[der],
            &[AlpnProtocol::Http2],
        )?),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(3),
        dns_servers_csv: Some(String::from("127.0.0.1")),
        ..ClientConfig::default()
    };
    let mut client = HttpClient::new(&mut proactor, client_config)?;
    client.resolve_host("localhost", port, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);

    let ok_count = Rc::new(Cell::new(0u32));
    let cancel_count = Rc::new(Cell::new(0u32));
    let other_count = Rc::new(Cell::new(0u32));
    let mut cancel_id = None;
    for index in 0..4u8 {
        let ok_count = Rc::clone(&ok_count);
        let cancel_count = Rc::clone(&cancel_count);
        let other_count = Rc::clone(&other_count);
        let request = Request::post(
            &format!("https://localhost:{port}/echo"),
            Bytes::copy_from_slice(&[index]),
        )?;
        let id = client.submit(
            &mut proactor,
            request,
            move |_ctx, _id, result| match result {
                Ok(response)
                    if response.status == StatusCode::OK && response.body.as_ref() == [index] =>
                {
                    ok_count.set(ok_count.get().saturating_add(1));
                }
                Err(Error::Cancelled) => cancel_count.set(cancel_count.get().saturating_add(1)),
                _ => other_count.set(other_count.get().saturating_add(1)),
            },
        )?;
        if index == 3 {
            cancel_id = Some(id);
        }
    }
    let Some(cancel_id) = cancel_id else {
        return Err(Error::InvalidState(String::from("missing cancel target")));
    };
    if !client.cancel(&mut proactor, cancel_id) {
        return Err(Error::InvalidState(String::from(
            "cancel missed the in-flight stream",
        )));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        server.drive(&mut proactor)?;
        client.drive_with(&mut proactor, &mut server)?;
        if ok_count.get() + cancel_count.get() + other_count.get() == 4 {
            break;
        }
    }
    if ok_count.get() != 3 || cancel_count.get() != 1 || other_count.get() != 0 {
        return Err(Error::InvalidState(format!(
            "expected 3 ok and 1 cancel, got ok={} cancel={} other={}",
            ok_count.get(),
            cancel_count.get(),
            other_count.get()
        )));
    }
    server.initiate_graceful_shutdown(&mut proactor)?;
    println!("http/2 tls multiplex ok port={port} streams=3 cancelled=1");
    Ok(())
}
