//! Loopback DNS, TLS, and proactor helpers for the nexora suites.
//!
//! DNS sockets and delayed replies advance on the same thread as the proactor
//! through `drive_until`.

#![allow(dead_code)]
mod dns;

use std::{
    cell::{Cell, RefCell},
    fs::File,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

#[allow(unused_imports)]
pub use dns::{DnsAction, DnsPlan, DnsStep, MockDns};
use nexora::{
    AlpnProtocol, Bytes, ClientConfig, PoolConfig, Proactor, ProactorConfig, RequestContext,
    Responder, Response, Result, ServerConfig, StatusCode, SubsystemId, TlsClientConfig,
    TlsServerConfig, WebSocketServerSession, http_service, websocket_handler,
};

/// Failure text returned by test assertions.
pub type TestResult = std::result::Result<(), String>;

/// Returns `Err` when `cond` is false.
///
/// # Errors
/// Returns `message` when `cond` is false.
///
/// # Panics
/// Does not panic.
pub fn check(cond: bool, message: impl Into<String>) -> TestResult {
    if cond { Ok(()) } else { Err(message.into()) }
}

/// Maps any error into the [`TestResult`] error string.
///
/// # Errors
/// Returns the error's display text when `result` is an error.
///
/// # Panics
/// Does not panic.
pub fn go<T, E: ToString>(result: std::result::Result<T, E>) -> std::result::Result<T, String> {
    result.map_err(|error| error.to_string())
}

/// Converts any error display into the suite error string.
pub trait IntoCheck<T> {
    /// Maps an error's display text into [`String`].
    ///
    /// # Errors
    /// Returns that text when `self` is an error.
    ///
    /// # Panics
    /// Does not panic.
    fn t(self) -> std::result::Result<T, String>;
}

impl<T, E: ToString> IntoCheck<T> for std::result::Result<T, E> {
    /// # Errors
    /// Returns the error display text.
    ///
    /// # Panics
    /// Does not panic.
    fn t(self) -> std::result::Result<T, String> {
        self.map_err(|error| error.to_string())
    }
}

/// Localhost certificate and the client policy that trusts it.
pub struct LocalIdentity {
    /// Server identity produced with the requested ALPN list.
    pub server: TlsServerConfig,
    /// DER trust anchor for [`TlsClientConfig::with_root_certificates`].
    pub cert_der: Vec<u8>,
    /// Client policy that trusts only `cert_der`.
    pub client: TlsClientConfig,
}

/// Builds a deterministic loopback TLS identity.
///
/// # Errors
/// Returns a TLS construction error from the proto identity helpers.
///
/// # Panics
/// Does not panic.
pub fn localhost_identity(alpn: &[AlpnProtocol]) -> Result<LocalIdentity> {
    let (server, cert_der) = TlsServerConfig::self_signed_for_localhost(alpn)?;
    let client = TlsClientConfig::with_root_certificates(std::slice::from_ref(&cert_der), alpn)?;
    Ok(LocalIdentity {
        server,
        cert_der,
        client,
    })
}

/// Counts descriptors in `/proc/self/fd`, excluding this read itself.
///
/// # Errors
/// Returns an I/O error when the process file descriptor directory cannot be read.
///
/// # Panics
/// Does not panic.
pub fn open_fd_count() -> io::Result<usize> {
    let mut count = 0usize;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        drop(entry?);
        count += 1;
    }
    Ok(count.saturating_sub(1))
}

/// Counts current-test and non-test tasks under `/proc/self/task`.
/// Sibling test tasks are excluded; tasks sharing the current name are retained.
///
/// # Errors
/// Returns an I/O error when the task directory or a live task name cannot be read.
///
/// # Panics
/// Does not panic.
pub fn thread_count() -> io::Result<usize> {
    let current = std::fs::read_to_string("/proc/thread-self/comm")?
        .trim()
        .to_owned();
    let mut count = 0usize;
    for entry in std::fs::read_dir("/proc/self/task")? {
        let comm = match std::fs::read_to_string(entry?.path().join("comm")) {
            Ok(comm) => comm,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let comm = comm.trim();
        if comm != current
            && ["sc_", "lc_", "e2e_", "it_", "support::"]
                .into_iter()
                .any(|prefix| comm.starts_with(prefix))
        {
            continue;
        }
        count += 1;
    }
    Ok(count)
}

/// Holds the test-suite file lock until dropped.
pub struct ExclusiveGuard {
    _file: File,
    _thread: std::marker::PhantomData<Rc<()>>,
}

/// Serializes cases that snapshot process-wide threads or descriptors.
///
/// One test binary runs several cases at once. Hold the guard for the whole
/// case so a sibling cannot open a socket mid-snapshot. Each guard opens its
/// own descriptor; closing it releases the file lock even during unwinding.
///
/// # Panics
/// Panics if the crate manifest cannot be opened or exclusively locked.
pub fn exclusive() -> ExclusiveGuard {
    let file = match File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")) {
        Ok(file) => file,
        Err(error) => panic!("cannot open test-suite lock: {error}"),
    };
    if let Err(error) = file.lock() {
        panic!("cannot acquire test-suite lock: {error}");
    }
    ExclusiveGuard {
        _file: file,
        _thread: std::marker::PhantomData,
    }
}

/// Public subsystem id, rejecting the reserved zero slot.
///
/// # Errors
/// Returns invalid state when `raw` is zero.
///
/// # Panics
/// Does not panic.
pub fn subsystem(raw: u8) -> Result<SubsystemId> {
    SubsystemId::new(raw).ok_or_else(|| nexora::Error::InvalidState(String::from("subsystem id 0")))
}

/// Thread-confined ring sized for loopback suites.
///
/// # Errors
/// Returns a proactor construction error.
///
/// # Panics
/// Does not panic.
pub fn proactor() -> Result<Proactor> {
    Proactor::new(ProactorConfig {
        entries: 256,
        staged_capacity: 1024,
        max_cqe_batch: 256,
        ..ProactorConfig::default()
    })
    .map_err(nexora::Error::from)
}

/// Client configuration pinned to explicit subsystem ids.
///
/// # Errors
/// Returns invalid state when a subsystem id is zero.
///
/// # Panics
/// Does not panic.
pub fn client_config(net: u8, dns: u8) -> Result<ClientConfig> {
    Ok(ClientConfig {
        net_subsystem: subsystem(net)?,
        dns_subsystem: subsystem(dns)?,
        prefer_http2: false,
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(3),
        pool: PoolConfig {
            max_connections_per_origin: 8,
            idle_timeout: Duration::from_secs(30),
            ..PoolConfig::default()
        },
        ..ClientConfig::default()
    })
}

/// Server configuration pinned to one subsystem id.
///
/// # Errors
/// Returns invalid state when `net` is zero.
///
/// # Panics
/// Does not panic.
pub fn server_config(net: u8) -> Result<ServerConfig> {
    Ok(ServerConfig {
        net_subsystem: subsystem(net)?,
        max_header_list_size: 16 * 1024,
        max_body_size: 1024 * 1024,
        ..ServerConfig::default()
    })
}

/// WebSocket client configuration pinned to explicit subsystem ids.
///
/// # Errors
/// Returns invalid state when a subsystem id is zero.
///
/// # Panics
/// Does not panic.
pub fn websocket_config(
    net: u8,
    dns: u8,
) -> Result<nexora::websocket_client::WebSocketClientConfig> {
    Ok(nexora::websocket_client::WebSocketClientConfig {
        net_subsystem: subsystem(net)?,
        dns_subsystem: subsystem(dns)?,
        connect_timeout: Duration::from_secs(2),
        ..nexora::websocket_client::WebSocketClientConfig::default()
    })
}

/// Spins on `turn` until it returns true or `budget` elapses.
///
/// Advances local DNS responders before and after each `turn`. `turn` must
/// drive the proactor. This function does not sleep.
///
/// # Errors
/// Returns the first error produced by `turn` or a local DNS responder.
///
/// # Panics
/// Does not panic.
pub fn drive_until(
    proactor: &mut Proactor,
    mut turn: impl FnMut(&mut Proactor) -> Result<bool>,
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        dns::poll_all()?;
        let ready = turn(proactor)?;
        dns::poll_all()?;
        if ready {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Shared callback cell. `calls` counts every store, including overwrites.
pub struct Slot<T> {
    value: Rc<RefCell<Option<T>>>,
    calls: Rc<Cell<usize>>,
}

impl<T> Clone for Slot<T> {
    fn clone(&self) -> Self {
        Self {
            value: Rc::clone(&self.value),
            calls: Rc::clone(&self.calls),
        }
    }
}

impl<T> Slot<T> {
    /// Empty slot with a zero call count.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: Rc::new(RefCell::new(None)),
            calls: Rc::new(Cell::new(0)),
        }
    }

    /// Stores `value` and increments the call count.
    ///
    /// # Panics
    /// Does not panic.
    pub fn set(&self, value: T) {
        *self.value.borrow_mut() = Some(value);
        self.calls.set(self.calls.get().saturating_add(1));
    }

    /// Removes the stored value.
    ///
    /// # Panics
    /// Does not panic.
    pub fn take(&self) -> Option<T> {
        self.value.borrow_mut().take()
    }

    /// Number of [`Self::set`] calls.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Behavior of [`Gate`] for `/echo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateMode {
    /// Plain text body, or `ok` when the request body is empty.
    Echo,
    /// Same body with `Transfer-Encoding: chunked`.
    Chunked,
    /// `302` to the configured location.
    Redirect,
}

/// Macro-routed loopback service used by the runtime suites.
pub struct Gate {
    mode: Rc<Cell<GateMode>>,
    held: Rc<RefCell<Option<Responder>>>,
    hits: Rc<Cell<u32>>,
    location: Rc<RefCell<String>>,
    param_hits: Rc<Cell<u32>>,
}

impl Gate {
    /// Echo service with no held responder.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn new(mode: GateMode) -> Self {
        Self {
            mode: Rc::new(Cell::new(mode)),
            held: Rc::new(RefCell::new(None)),
            hits: Rc::new(Cell::new(0)),
            location: Rc::new(RefCell::new(String::new())),
            param_hits: Rc::new(Cell::new(0)),
        }
    }

    /// Shared mode cell.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn mode(&self) -> Rc<Cell<GateMode>> {
        Rc::clone(&self.mode)
    }

    /// Responder parked by `GET /hold`.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn held(&self) -> Rc<RefCell<Option<Responder>>> {
        Rc::clone(&self.held)
    }

    /// Requests that entered a route handler.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn hits(&self) -> Rc<Cell<u32>> {
        Rc::clone(&self.hits)
    }

    /// Times `GET /item/{id}` observed `ctx.param("id")`.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn param_hits(&self) -> Rc<Cell<u32>> {
        Rc::clone(&self.param_hits)
    }

    /// Absolute `Location` used by [`GateMode::Redirect`].
    ///
    /// # Panics
    /// Does not panic.
    pub fn set_location(&self, location: impl Into<String>) {
        *self.location.borrow_mut() = location.into();
    }

    fn note(&self) {
        self.hits.set(self.hits.get().saturating_add(1));
    }

    fn echo_body(&self, req: &nexora::Request) -> Result<Response> {
        self.note();
        match self.mode.get() {
            GateMode::Redirect => Ok(Response::new(StatusCode::FOUND)
                .with_header("location", self.location.borrow().clone())),
            GateMode::Chunked => Ok(Response::text(StatusCode::OK, req.body.clone())
                .with_header("transfer-encoding", "chunked")),
            GateMode::Echo => {
                let body = if req.body.is_empty() {
                    Bytes::copy_from_slice(b"ok")
                } else {
                    req.body.clone()
                };
                Ok(Response::text(StatusCode::OK, body))
            }
        }
    }
}

#[http_service]
impl Gate {
    #[get("/echo")]
    fn get_echo(&mut self, _ctx: &mut RequestContext, req: nexora::Request) -> Result<Response> {
        self.echo_body(&req)
    }

    #[post("/echo")]
    fn post_echo(&mut self, _ctx: &mut RequestContext, req: nexora::Request) -> Result<Response> {
        self.echo_body(&req)
    }

    #[put("/echo")]
    fn put_echo(&mut self, _ctx: &mut RequestContext, req: nexora::Request) -> Result<Response> {
        self.echo_body(&req)
    }

    #[delete("/echo")]
    fn delete_echo(&mut self, _ctx: &mut RequestContext, req: nexora::Request) -> Result<Response> {
        self.echo_body(&req)
    }

    #[get("/hold")]
    fn hold(
        &mut self,
        _ctx: &mut RequestContext,
        _req: nexora::Request,
        responder: Responder,
    ) -> Result<()> {
        self.note();
        *self.held.borrow_mut() = Some(responder);
        Ok(())
    }

    #[get("/drop")]
    fn drop_responder(
        &mut self,
        _ctx: &mut RequestContext,
        _req: nexora::Request,
        responder: Responder,
    ) -> Result<()> {
        self.note();
        drop(responder);
        Ok(())
    }

    #[get("/item/{id}")]
    fn item(&mut self, ctx: &mut RequestContext, req: nexora::Request) -> Result<Response> {
        self.note();
        let tail = req.path().rsplit('/').next().unwrap_or("").to_owned();
        if ctx.param("id") == Some(tail.as_str()) {
            self.param_hits.set(self.param_hits.get().saturating_add(1));
        }
        let id = ctx.param("id").unwrap_or(tail.as_str()).to_owned();
        Ok(Response::text(StatusCode::OK, id))
    }
}

/// WebSocket echo that records session ids and text payloads.
pub struct WebSocketEcho {
    sessions: Rc<RefCell<Vec<u64>>>,
    texts: Rc<RefCell<Vec<String>>>,
}

impl WebSocketEcho {
    /// Empty echo handler.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Rc::new(RefCell::new(Vec::new())),
            texts: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Session ids passed to `on_open`, in arrival order.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn sessions(&self) -> Rc<RefCell<Vec<u64>>> {
        Rc::clone(&self.sessions)
    }

    /// Text frames delivered to the handler.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn texts(&self) -> Rc<RefCell<Vec<String>>> {
        Rc::clone(&self.texts)
    }
}

impl Default for WebSocketEcho {
    fn default() -> Self {
        Self::new()
    }
}

#[websocket_handler]
impl WebSocketEcho {
    fn on_open(&mut self, session: &mut WebSocketServerSession) -> Result<()> {
        self.sessions.borrow_mut().push(session.id().raw());
        Ok(())
    }

    fn on_text(&mut self, session: &mut WebSocketServerSession, text: String) -> Result<()> {
        self.texts.borrow_mut().push(text.clone());
        if text == "subscribe" {
            session.send_text("ack")?;
        } else {
            session.send_text(text)?;
        }
        Ok(())
    }

    fn on_binary(&mut self, session: &mut WebSocketServerSession, data: Bytes) -> Result<()> {
        session.send_binary(data)?;
        Ok(())
    }

    fn on_close(
        &mut self,
        _session: &mut WebSocketServerSession,
        _close: Option<nexora::WebSocketCloseFrame>,
    ) -> Result<()> {
        Ok(())
    }
}

/// Loopback address with an ephemeral port.
///
/// # Panics
/// Does not panic.
#[must_use]
pub fn ephemeral() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// IPv4 loopback address.
///
/// # Panics
/// Does not panic.
#[must_use]
pub fn ipv4_loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}
