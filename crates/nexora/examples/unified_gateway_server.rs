//! One listener demuxes cleartext HTTP/1.1, HTTP/2 prior knowledge, and WebSocket.
//!
//! Each client uses its own proactor subsystem ids. Only the client that owns
//! in-flight operations polls the ring and explicitly routes server CQEs.
//! Each HTTP client retires its work before the next protocol starts.

use std::{
    cell::{Cell, RefCell},
    net::{Ipv4Addr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use nexora::{
    ClientConfig, Error, Headers, HttpClient, HttpServer, HttpService, Proactor, Request,
    RequestContext, Responder, Response, ServerConfig, StatusCode, SubsystemId, WebSocketClient,
    WebSocketMessage, WebSocketServerSession, WebSocketSessionId, WebSocketUpgradeHandler,
    websocket_client::{WebSocketClientConfig, WebSocketEvent},
};

struct Gateway;

impl HttpService for Gateway {
    /// Tags the body with the request path so each protocol is observable.
    ///
    /// # Errors
    /// Returns a responder error when the connection is already closed.
    ///
    /// # Panics
    /// This method does not panic.
    fn call(
        &mut self,
        _ctx: &mut RequestContext,
        req: Request,
        responder: Responder,
    ) -> nexora::Result<()> {
        let body: &[u8] = if req.path() == "/h2" { b"h2" } else { b"h1" };
        responder.respond(Response::text(StatusCode::OK, body))
    }
}

struct EchoPush {
    server_id: Rc<Cell<Option<WebSocketSessionId>>>,
}

impl WebSocketUpgradeHandler for EchoPush {
    /// Records the upgraded session for a later push.
    ///
    /// # Errors
    /// This method does not return errors.
    ///
    /// # Panics
    /// This method does not panic.
    fn on_open(&mut self, session: &mut WebSocketServerSession) -> nexora::Result<()> {
        self.server_id.set(Some(session.id()));
        Ok(())
    }

    /// Echoes text and binary frames.
    ///
    /// # Errors
    /// Returns a session error when the socket can no longer send.
    ///
    /// # Panics
    /// This method does not panic.
    fn on_message(
        &mut self,
        session: &mut WebSocketServerSession,
        message: WebSocketMessage,
    ) -> nexora::Result<()> {
        match message {
            WebSocketMessage::Text(_) | WebSocketMessage::Binary(_) => session.send(message),
            WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_) | WebSocketMessage::Close(_) => {
                Ok(())
            }
        }
    }
}

fn main() -> nexora::Result<()> {
    let mut proactor = Proactor::builder().build()?;
    let server_id = Rc::new(Cell::new(None));
    let server_config = ServerConfig {
        net_subsystem: SubsystemId::new_unchecked(3),
        ..ServerConfig::default()
    };
    let mut server = HttpServer::bind(
        &mut proactor,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_config,
        Gateway,
    )?
    .with_websocket_handler(
        "/ws",
        EchoPush {
            server_id: Rc::clone(&server_id),
        },
    );
    let port = server.local_addr().port();

    http1_once(&mut proactor, &mut server, port)?;
    http2_once(&mut proactor, &mut server, port)?;
    websocket_once(&mut proactor, &mut server, port, &server_id)?;
    server.initiate_graceful_shutdown(&mut proactor)?;
    println!("unified gateway ok port={port} http1+h2c+websocket");
    Ok(())
}

fn http1_once(
    proactor: &mut Proactor,
    server: &mut HttpServer<Gateway>,
    port: u16,
) -> nexora::Result<()> {
    let config = ClientConfig {
        net_subsystem: SubsystemId::new_unchecked(1),
        dns_subsystem: SubsystemId::new_unchecked(2),
        prefer_http2: false,
        http2_prior_knowledge: false,
        dns_servers_csv: Some(String::from("127.0.0.1")),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        ..ClientConfig::default()
    };
    let mut client = HttpClient::new(proactor, config)?;
    let body = Rc::new(RefCell::new(None));
    let slot = Rc::clone(&body);
    let request = Request::get(&format!("http://127.0.0.1:{port}/plain"))?;
    client.submit(proactor, request, move |_ctx, _id, result| {
        *slot.borrow_mut() = Some(
            result
                .map(|response| response.body.as_ref().to_vec())
                .map_err(|error| error.to_string()),
        );
    })?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        server.drive(proactor)?;
        client.drive_with(proactor, &mut *server)?;
        if body.borrow().is_some() {
            break;
        }
    }
    client.shutdown_with(proactor, server)?;
    match body.borrow().as_ref() {
        Some(Ok(bytes)) if bytes.as_slice() == b"h1" => Ok(()),
        Some(Ok(_)) => Err(Error::InvalidState(String::from("unexpected http/1 body"))),
        Some(Err(error)) => Err(Error::InvalidState(error.clone())),
        None => Err(Error::Timeout),
    }
}

fn http2_once(
    proactor: &mut Proactor,
    server: &mut HttpServer<Gateway>,
    port: u16,
) -> nexora::Result<()> {
    let config = ClientConfig {
        net_subsystem: SubsystemId::new_unchecked(4),
        dns_subsystem: SubsystemId::new_unchecked(5),
        prefer_http2: true,
        http2_prior_knowledge: true,
        dns_servers_csv: Some(String::from("127.0.0.1")),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        ..ClientConfig::default()
    };
    let mut client = HttpClient::new(proactor, config)?;
    let body = Rc::new(RefCell::new(None));
    let slot = Rc::clone(&body);
    let request = Request::get(&format!("http://127.0.0.1:{port}/h2"))?;
    client.submit(proactor, request, move |_ctx, _id, result| {
        *slot.borrow_mut() = Some(
            result
                .map(|response| response.body.as_ref().to_vec())
                .map_err(|error| error.to_string()),
        );
    })?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        server.drive(proactor)?;
        client.drive_with(proactor, &mut *server)?;
        if body.borrow().is_some() {
            break;
        }
    }
    client.shutdown_with(proactor, server)?;
    match body.borrow().as_ref() {
        Some(Ok(bytes)) if bytes.as_slice() == b"h2" => Ok(()),
        Some(Ok(_)) => Err(Error::InvalidState(String::from("unexpected http/2 body"))),
        Some(Err(error)) => Err(Error::InvalidState(error.clone())),
        None => Err(Error::Timeout),
    }
}

fn websocket_once(
    proactor: &mut Proactor,
    server: &mut HttpServer<Gateway>,
    port: u16,
    server_id: &Rc<Cell<Option<WebSocketSessionId>>>,
) -> nexora::Result<()> {
    let config = WebSocketClientConfig {
        dns_subsystem: SubsystemId::new_unchecked(6),
        net_subsystem: SubsystemId::new_unchecked(7),
        dns_servers_csv: Some(String::from("127.0.0.1")),
        connect_timeout: Duration::from_secs(2),
        ..WebSocketClientConfig::default()
    };
    let mut client = WebSocketClient::new(proactor, config)?;
    let opened = Rc::new(Cell::new(false));
    let flag = Rc::clone(&opened);
    let url = format!("ws://127.0.0.1:{port}/ws");
    let session = client.connect(proactor, &url, Headers::new(), move |_ctx, _id, result| {
        flag.set(result.is_ok());
    })?;
    let texts = Rc::new(RefCell::new(Vec::new()));
    let inbox = Rc::clone(&texts);
    client.set_message_handler(session, move |_ctx, _session, event| {
        if let WebSocketEvent::Text(text) = event {
            inbox.borrow_mut().push(text);
        }
    })?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        server.drive(proactor)?;
        client.drive_with(proactor, &mut *server)?;
        if opened.get() && client.is_open(session) {
            break;
        }
    }
    if !client.is_open(session) {
        return Err(Error::Timeout);
    }
    client.send_text(proactor, session, "gw")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        server.drive(proactor)?;
        client.drive_with(proactor, &mut *server)?;
        if texts.borrow().iter().any(|text| text == "gw") {
            break;
        }
    }
    let Some(id) = server_id.get() else {
        return Err(Error::InvalidState(String::from(
            "missing websocket session",
        )));
    };
    server.websocket_send(id, WebSocketMessage::Text(String::from("gw-push")))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        server.drive(proactor)?;
        client.drive_with(proactor, &mut *server)?;
        if texts.borrow().iter().any(|text| text == "gw-push") {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}
