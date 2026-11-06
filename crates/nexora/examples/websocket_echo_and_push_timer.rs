//! WebSocket echo plus a server push released by a drive-loop timer.
//!
//! The timer is an [`std::time::Instant`] deadline. The loop keeps polling the
//! ring and never sleeps the thread. The push uses [`nexora::HttpServer::websocket_send`]
//! with the session id captured in `on_open`.

use std::{
    cell::{Cell, RefCell},
    net::{Ipv4Addr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use nexora::{
    Error, Headers, HttpServer, HttpService, Proactor, Request, RequestContext, Responder,
    Response, ServerConfig, StatusCode, SubsystemId, WebSocketClient, WebSocketMessage,
    WebSocketServerSession, WebSocketSessionId, WebSocketUpgradeHandler,
    websocket_client::{WebSocketClientConfig, WebSocketEvent},
};

struct IgnoreHttp;

impl HttpService for IgnoreHttp {
    /// Rejects plain HTTP that did not upgrade.
    ///
    /// # Errors
    /// Returns a responder error when the connection is already closed.
    ///
    /// # Panics
    /// This method does not panic.
    fn call(
        &mut self,
        _ctx: &mut RequestContext,
        _req: Request,
        responder: Responder,
    ) -> nexora::Result<()> {
        responder.respond(Response::text(StatusCode::NOT_FOUND, "not found"))
    }
}

struct EchoPush {
    server_id: Rc<Cell<Option<WebSocketSessionId>>>,
}

impl WebSocketUpgradeHandler for EchoPush {
    /// Records the session that later receives the timer push.
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

    /// Echoes data frames. Control frames are answered by the server codec.
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
        IgnoreHttp,
    )?
    .with_websocket_handler(
        "/ws",
        EchoPush {
            server_id: Rc::clone(&server_id),
        },
    );
    let port = server.local_addr().port();

    let websocket_config = WebSocketClientConfig {
        dns_subsystem: SubsystemId::new_unchecked(1),
        net_subsystem: SubsystemId::new_unchecked(2),
        dns_servers_csv: Some(String::from("127.0.0.1")),
        connect_timeout: Duration::from_secs(2),
        ..WebSocketClientConfig::default()
    };
    let mut client = WebSocketClient::new(&mut proactor, websocket_config)?;
    let opened = Rc::new(Cell::new(false));
    let opened_flag = Rc::clone(&opened);
    let open_error = Rc::new(RefCell::new(None));
    let open_slot = Rc::clone(&open_error);
    let url = format!("ws://127.0.0.1:{port}/ws");
    let session = client.connect(
        &mut proactor,
        &url,
        Headers::new(),
        move |_ctx, _id, result| {
            opened_flag.set(result.is_ok());
            if let Err(error) = result {
                *open_slot.borrow_mut() = Some(error.to_string());
            }
        },
    )?;
    let texts = Rc::new(RefCell::new(Vec::new()));
    let inbox = Rc::clone(&texts);
    client.set_message_handler(session, move |_ctx, _session, event| {
        if let WebSocketEvent::Text(text) = event {
            inbox.borrow_mut().push(text);
        }
    })?;

    if let Err(error) = pump(&mut proactor, &mut server, &mut client, |client| {
        opened.get() && client.is_open(session)
    }) {
        if let Some(detail) = open_error.borrow().clone() {
            return Err(Error::InvalidState(detail));
        }
        return Err(error);
    }
    client.send_text(&mut proactor, session, "hello")?;
    pump(&mut proactor, &mut server, &mut client, |_client| {
        texts.borrow().iter().any(|text| text == "hello")
    })?;

    let fire_at = Instant::now() + Duration::from_millis(30);
    while Instant::now() < fire_at {
        server.drive(&mut proactor)?;
        client.drive_with(&mut proactor, &mut server)?;
    }
    let Some(id) = server_id.get() else {
        return Err(Error::InvalidState(String::from(
            "websocket upgrade did not open a server session",
        )));
    };
    server.websocket_send(id, WebSocketMessage::Text(String::from("tick")))?;
    pump(&mut proactor, &mut server, &mut client, |_client| {
        texts.borrow().iter().any(|text| text == "tick")
    })?;
    println!("websocket echo and push ok port={port}");
    Ok(())
}

fn pump(
    proactor: &mut Proactor,
    server: &mut HttpServer<IgnoreHttp>,
    client: &mut WebSocketClient,
    ready: impl Fn(&WebSocketClient) -> bool,
) -> nexora::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        server.drive(proactor)?;
        client.drive_with(proactor, &mut *server)?;
        if ready(client) {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}
