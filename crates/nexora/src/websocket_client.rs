//! Client-side RFC 6455 driver: DNS, TCP, TLS, HTTP upgrade, and message framing.

mod driver;
mod session;
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    hash::{BuildHasher, Hasher},
    net::{IpAddr, SocketAddr},
    os::fd::RawFd,
    rc::Rc,
    time::Duration,
};

use cares::{
    ARecord, AaaaRecord, DnsRecordType, DnsSection, ProactorResolver, options::ResolverOptions,
};
use driver::{
    PeerAddr, close_raw, drain_tls, handshake_seed, invalid, open_socket, operation_id, push_wire,
    system_servers_csv,
};
use liburing::{
    Completion, CompletionDispatcher, OperationId, OperationPayload, Proactor, SubmissionContext,
    SubsystemId,
    ops::{Timeout, net},
};
use nexora_proto::{
    AlpnProtocol, Bytes, BytesMut, Headers, Http1ClientCodec, Method, ProtoError, TlsClientConfig,
    TlsSession, Uri, WebSocketCloseCode, WebSocketCloseFrame, WebSocketCodec, WebSocketConfig,
    WebSocketHandshake, WebSocketMessage, WebSocketRole,
};
use session::{DnsOutcome, Session, SessionPhase};

use crate::{
    error::{Error, Result},
    inbox::{ClientContext, InboxCommand, SubsystemInbox, WebSocketSessionId},
};
/// Fixed receive buffer size owned by every session.
const RX_BUFFER_SIZE: usize = 64 * 1024;
/// Ciphertext staging size used while draining TLS output.
const TLS_CHUNK_SIZE: usize = 16 * 1024;
const DNS_BRIDGE_CAPACITY: usize = 8;
/// Retry bound for one TLS write drain.
const MAX_WRITE_ROUNDS: usize = 64;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Bit position of the completion tag inside a 56-bit operation payload.
const TAG_SHIFT: u64 = 52;
/// Mask covering the session identifier stored below the tag.
const ID_MASK: u64 = (1 << TAG_SHIFT) - 1;
const TAG_CONNECT: u64 = 1;
const TAG_RECV: u64 = 2;
const TAG_SEND: u64 = 3;
const TAG_CLOSE: u64 = 4;
const TAG_CANCEL: u64 = 5;
const TAG_CONNECT_TIMEOUT: u64 = 6;
const TAG_PING_TIMEOUT: u64 = 7;
/// Callback fired once when a connection opens or fails before opening.
type OpenCallback = Box<dyn FnOnce(&mut ClientContext, WebSocketSessionId, Result<()>) + 'static>;
/// Message and close sink registered for a session.
type EventCallback =
    Box<dyn FnMut(&mut ClientContext, &mut WebSocketSession, WebSocketEvent) + 'static>;

/// Client-wide limits for WebSocket connections, DNS, and keepalive.
#[derive(Debug, Clone)]
pub struct WebSocketClientConfig {
    /// Deadline for one TCP connect attempt.
    pub connect_timeout: Duration,
    /// Largest accepted incoming frame payload.
    pub max_frame_size: usize,
    /// Largest reassembled incoming message.
    pub max_message_size: usize,
    /// TLS policy for `wss` URLs; its ALPN list must offer `http/1.1`.
    pub tls_config: Option<TlsClientConfig>,
    /// Comma-separated DNS servers; `None` reads the system configuration.
    pub dns_servers_csv: Option<String>,
    /// Subsystem that receives resolver completions.
    pub dns_subsystem: SubsystemId,
    /// Subsystem that receives socket completions.
    pub net_subsystem: SubsystemId,
    /// Delay between keepalive pings; `None` disables them.
    pub ping_interval: Option<Duration>,
}
impl Default for WebSocketClientConfig {
    /// Creates the default policy: 10 s connect, 1 MiB frames, 16 MiB messages,
    /// no TLS, no keepalive, DNS on subsystem 1, sockets on subsystem 2.
    /// # Errors
    /// This operation does not return errors.
    /// # Panics
    /// This function does not panic.
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            tls_config: None,
            dns_servers_csv: None,
            dns_subsystem: SubsystemId::new_unchecked(1),
            net_subsystem: SubsystemId::new_unchecked(2),
            ping_interval: None,
        }
    }
}

/// Event delivered to the sink registered with [`WebSocketClient::set_message_handler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebSocketEvent {
    Text(String),
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close(Option<WebSocketCloseFrame>),
}

/// Per-session handle passed to message callbacks; mutations are staged through
/// [`ClientContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketSession {
    id: WebSocketSessionId,
}
impl WebSocketSession {
    /// Returns the identifier used by [`WebSocketClient`] methods.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn id(&self) -> WebSocketSessionId {
        self.id
    }
    /// Stages one text message for the drive loop.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn send_text(&mut self, ctx: &mut ClientContext, text: impl Into<String>) {
        ctx.websocket_send(self.id, WebSocketMessage::Text(text.into()));
    }
    /// Stages one binary message for the drive loop.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn send_binary(&mut self, ctx: &mut ClientContext, data: impl Into<Bytes>) {
        ctx.websocket_send(self.id, WebSocketMessage::Binary(data.into()));
    }
    /// Stages one ping frame for the drive loop.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn ping(&mut self, ctx: &mut ClientContext, payload: impl Into<Bytes>) {
        ctx.websocket_send(self.id, WebSocketMessage::Ping(payload.into()));
    }
    /// Stages the close handshake for the drive loop.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn close(&mut self, ctx: &mut ClientContext, close: Option<WebSocketCloseFrame>) {
        ctx.websocket_close(self.id, close);
    }
}

/// Client-side WebSocket driver over one shared proactor.
pub struct WebSocketClient {
    config: WebSocketClientConfig,
    inbox: SubsystemInbox,
    dns: ProactorResolver,
    sessions: HashMap<WebSocketSessionId, Session>,
    handlers: HashMap<WebSocketSessionId, EventCallback>,
    static_hosts: HashMap<(String, u16), Vec<SocketAddr>>,
    dns_waiters: HashMap<u64, WebSocketSessionId>,
    dns_outcomes: Rc<RefCell<VecDeque<DnsOutcome>>>,
    next_lookup: u64,
}

impl WebSocketClient {
    /// Creates a client and its shared-ring DNS driver.
    /// # Errors
    /// Returns an error for reserved or duplicated subsystem identifiers, an
    /// invalid resolver configuration, or a driver that cannot be created.
    /// # Panics
    /// This function does not panic.
    pub fn new(proactor: &mut Proactor, config: WebSocketClientConfig) -> Result<Self> {
        if config.dns_subsystem == SubsystemId::INTERNAL
            || config.net_subsystem == SubsystemId::INTERNAL
            || config.dns_subsystem == config.net_subsystem
        {
            return Err(invalid(
                "subsystems must be distinct non-internal identifiers",
            ));
        }
        let servers = config
            .dns_servers_csv
            .clone()
            .unwrap_or_else(system_servers_csv);
        let options = ResolverOptions::builder()
            .tries(1)
            .timeout(DNS_QUERY_TIMEOUT)
            .query_cache_ttl(Duration::ZERO)
            .build()?;
        let dns =
            ProactorResolver::new(config.dns_subsystem, options, &servers, DNS_BRIDGE_CAPACITY)?;
        let mut client = Self {
            config,
            inbox: SubsystemInbox::new(),
            dns,
            sessions: HashMap::new(),
            handlers: HashMap::new(),
            static_hosts: HashMap::new(),
            dns_waiters: HashMap::new(),
            dns_outcomes: Rc::new(RefCell::new(VecDeque::new())),
            next_lookup: 1,
        };
        client.dns.flush(proactor)?;
        Ok(client)
    }
    /// Pins `host:port` to `ips`, taking precedence over resolver answers.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn resolve_host(&mut self, host: impl Into<String>, port: u16, ips: Vec<IpAddr>) {
        let addrs = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        self.static_hosts.insert((host.into(), port), addrs);
    }
    /// Starts an RFC 6455 upgrade; `on_open` fires exactly once with the result.
    /// # Errors
    /// Returns an error for a malformed or non-WebSocket URL, a `wss` URL
    /// without a TLS configuration, or a DNS query that cannot be submitted.
    /// On `Err` no session exists and `on_open` is dropped without being called;
    /// every later failure reaches it exactly once.
    /// # Panics
    /// This function does not panic.
    pub fn connect<F>(
        &mut self,
        proactor: &mut Proactor,
        url: &str,
        extra: Headers,
        on_open: F,
    ) -> Result<WebSocketSessionId>
    where
        F: FnOnce(&mut ClientContext, WebSocketSessionId, Result<()>) + 'static,
    {
        let uri = Uri::parse(url).map_err(|error| Error::InvalidUri(error.to_string()))?;
        if !uri.scheme().is_websocket() {
            return Err(Error::InvalidUri(String::from(
                "the URL requires a ws or wss scheme",
            )));
        }
        if uri.scheme().is_tls() && self.config.tls_config.is_none() {
            return Err(invalid("a wss URL requires a TLS client configuration"));
        }
        let id = self.inbox.next_websocket_session_id();
        let (host, port) = (uri.host().to_owned(), uri.port());
        let key = WebSocketHandshake::generate_key(handshake_seed(id));
        let mut session = Session::new(id, uri, &self.config, extra, key, Box::new(on_open));
        let addr = match self.static_hosts.get(&(host.clone(), port)) {
            Some(addrs) => addrs.first().copied(),
            None => host
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, port)),
        };
        if let Some(addr) = addr {
            session.phase = SessionPhase::Connecting;
            self.sessions.insert(id, session);
            if let Err(error) = self.begin_connect(proactor, id, addr) {
                drop(self.sessions.remove(&id));
                return Err(error);
            }
            return Ok(id);
        }
        self.sessions.insert(id, session);
        if let Err(error) = self.start_dns(proactor, id, &host, port) {
            drop(self.sessions.remove(&id));
            return Err(error);
        }
        Ok(id)
    }
    /// Registers the message and close sink for a session.
    /// # Errors
    /// Returns an error when `session` is not tracked by this client.
    /// # Panics
    /// This function does not panic.
    pub fn set_message_handler<F>(&mut self, session: WebSocketSessionId, on_event: F) -> Result<()>
    where
        F: FnMut(&mut ClientContext, &mut WebSocketSession, WebSocketEvent) + 'static,
    {
        if !self.sessions.contains_key(&session) {
            return Err(invalid("unknown WebSocket session"));
        }
        self.handlers.insert(session, Box::new(on_event));
        Ok(())
    }
    /// Sends one text message.
    /// # Errors
    /// Returns an error when the session is unknown or not open, or the message
    /// cannot be encoded in the current codec state.
    /// # Panics
    /// This function does not panic.
    pub fn send_text(
        &mut self,
        proactor: &mut Proactor,
        session: WebSocketSessionId,
        text: impl Into<String>,
    ) -> Result<()> {
        self.send_message(proactor, session, WebSocketMessage::Text(text.into()))
    }
    /// Sends one binary message.
    /// # Errors
    /// Returns an error when the session is unknown or not open, or the message
    /// cannot be encoded in the current codec state.
    /// # Panics
    /// This function does not panic.
    pub fn send_binary(
        &mut self,
        proactor: &mut Proactor,
        session: WebSocketSessionId,
        data: impl Into<Bytes>,
    ) -> Result<()> {
        self.send_message(proactor, session, WebSocketMessage::Binary(data.into()))
    }
    /// Sends one ping frame.
    /// # Errors
    /// Returns an error when the session is unknown or not open, or the frame
    /// cannot be encoded in the current codec state.
    /// # Panics
    /// This function does not panic.
    pub fn ping(
        &mut self,
        proactor: &mut Proactor,
        session: WebSocketSessionId,
        payload: impl Into<Bytes>,
    ) -> Result<()> {
        self.send_message(proactor, session, WebSocketMessage::Ping(payload.into()))
    }
    /// Sends one unsolicited pong frame.
    /// # Errors
    /// Returns an error when the session is unknown or not open, or the frame
    /// cannot be encoded in the current codec state.
    /// # Panics
    /// This function does not panic.
    pub fn pong(
        &mut self,
        proactor: &mut Proactor,
        session: WebSocketSessionId,
        payload: impl Into<Bytes>,
    ) -> Result<()> {
        self.send_message(proactor, session, WebSocketMessage::Pong(payload.into()))
    }
    /// Starts the close handshake and tears down after the frame leaves the wire.
    /// # Errors
    /// Returns an error when the session is unknown or the frame cannot be encoded.
    /// # Panics
    /// This function does not panic.
    pub fn close(
        &mut self,
        proactor: &mut Proactor,
        session: WebSocketSessionId,
        close: Option<WebSocketCloseFrame>,
    ) -> Result<()> {
        if !self.sessions.contains_key(&session) {
            return Err(invalid("unknown WebSocket session"));
        }
        self.request_close(session, close);
        self.pump(proactor)
    }
    /// Drains staged commands, DNS outcomes, completions, and expired timers.
    ///
    /// Returns the number of inbox commands, DNS outcomes, and completions
    /// handled during this turn.
    /// # Errors
    /// Returns a staging, submission, protocol, or resolver error. Sessions
    /// whose work could not be staged stay tracked and are retried next turn.
    /// # Panics
    /// This function does not panic.
    pub fn drive(&mut self, proactor: &mut Proactor) -> Result<usize> {
        self.drive_with(proactor, &mut crate::dispatch::RejectForeign)
    }
    /// Advances sessions while routing other subsystems through `peer`.
    /// # Errors
    /// Returns protocol, DNS, submission, or completion-routing errors.
    /// # Panics
    /// User callbacks may panic.
    pub fn drive_with<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        proactor: &mut Proactor,
        peer: &mut D,
    ) -> Result<usize> {
        let mut processed = self.drain_inbox();
        processed += self.apply_dns(proactor)?;
        self.pump(proactor)?;
        self.dns.flush(proactor)?;
        let mut failure: Option<Error> = None;
        let harvested = proactor.tick(
            &mut |completion: Completion, submissions: &mut SubmissionContext<'_>| {
                if !crate::dispatch::CompletionRoute::accepts(
                    self,
                    completion.operation_id.subsystem_id(),
                ) {
                    return peer.dispatch(completion, submissions);
                }
                if let Err(error) = self.on_completion(completion, submissions)
                    && failure.is_none()
                {
                    failure = Some(error);
                }
                Ok(())
            },
        )?;
        processed += harvested;
        self.pump(proactor)?;
        self.dns.flush(proactor)?;
        proactor.submit()?;
        match failure {
            Some(error) => Err(error),
            None => Ok(processed),
        }
    }
    /// Reports whether the session completed its upgrade and is still writable.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn is_open(&self, session: WebSocketSessionId) -> bool {
        self.sessions
            .get(&session)
            .is_some_and(|owned| owned.phase == SessionPhase::Open)
    }
    /// Returns the number of sessions still tracked by this client.
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// This function does not return errors.
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
    fn send_message(
        &mut self,
        proactor: &mut Proactor,
        session: WebSocketSessionId,
        message: WebSocketMessage,
    ) -> Result<()> {
        let Some(mut owned) = self.sessions.remove(&session) else {
            return Err(invalid("unknown WebSocket session"));
        };
        let allowed = owned.phase == SessionPhase::Open;
        let result = if allowed {
            owned.queue_message(message).map_err(Error::Proto)
        } else {
            Err(invalid("WebSocket session is not open"))
        };
        self.sessions.insert(session, owned);
        result?;
        self.pump(proactor)
    }
    /// Applies the staged commands this client owns.
    ///
    /// Sends and closes addressed to an unknown or retired session are dropped:
    /// the identifier is only valid while the session is tracked. Commands
    /// staged for other subsystems are discarded explicitly, because this loop
    /// owns none of those resources.
    fn drain_inbox(&mut self) -> usize {
        let mut applied = 0;
        while let Some(command) = self.inbox.pop() {
            applied += 1;
            match command {
                InboxCommand::WebSocketSend {
                    session_id,
                    message,
                } => self.queue_message(session_id, message),
                InboxCommand::WebSocketClose { session_id, close } => {
                    self.request_close(session_id, close)
                }
                InboxCommand::Submit(_)
                | InboxCommand::Cancel(_)
                | InboxCommand::SetTimer(_)
                | InboxCommand::DnsResolved(_)
                | InboxCommand::Respond(_) => {}
            }
        }
        applied
    }
    fn queue_message(&mut self, session: WebSocketSessionId, message: WebSocketMessage) {
        let Some(mut owned) = self.sessions.remove(&session) else {
            return;
        };
        if owned.phase == SessionPhase::Open {
            let closing = matches!(message, WebSocketMessage::Close(_));
            if let Err(error) = owned.queue_message(message) {
                self.fail(&mut owned, Error::Proto(error));
            } else if closing {
                owned.phase = SessionPhase::CloseFlush;
            }
        }
        self.sessions.insert(session, owned);
    }
    fn request_close(&mut self, session: WebSocketSessionId, close: Option<WebSocketCloseFrame>) {
        let Some(mut owned) = self.sessions.remove(&session) else {
            return;
        };
        // A repeated close request is idempotent: the handshake is already
        // running, and a request from inside the peer-close callback must not
        // abort the reply frame that is about to be queued.
        if !owned.phase.is_teardown() && !owned.phase.is_closing() {
            if owned.phase == SessionPhase::Open {
                match owned.queue_message(WebSocketMessage::Close(close)) {
                    Ok(()) => owned.phase = SessionPhase::CloseFlush,
                    Err(error) => self.fail(&mut owned, Error::Proto(error)),
                }
            } else {
                // Closing before the upgrade completes cancels the attempt.
                self.fail(&mut owned, Error::Cancelled);
            }
        }
        self.sessions.insert(session, owned);
    }
    fn start_dns(
        &mut self,
        proactor: &mut Proactor,
        id: WebSocketSessionId,
        host: &str,
        port: u16,
    ) -> Result<()> {
        let lookup = self.next_lookup;
        self.next_lookup = self.next_lookup.wrapping_add(1);
        self.dns_waiters.insert(lookup, id);
        if let Some(owned) = self.sessions.get_mut(&id) {
            owned.lookup = Some(lookup);
            owned.dns_left = 2;
        }
        let mut handles = Vec::with_capacity(2);
        for record_type in [DnsRecordType::A, DnsRecordType::AAAA] {
            let outcomes = Rc::clone(&self.dns_outcomes);
            let submitted =
                self.dns
                    .resolver
                    .submit_query(host, record_type, move |_ctx, outcome| {
                        let mut addrs = Vec::new();
                        if let Some(record) = outcome.record.as_ref() {
                            addrs.extend(
                                record
                                    .records::<ARecord>(DnsSection::Answer)
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|a| SocketAddr::new(IpAddr::V4(a.address), port)),
                            );
                            addrs.extend(
                                record
                                    .records::<AaaaRecord>(DnsSection::Answer)
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|a| SocketAddr::new(IpAddr::V6(a.address), port)),
                            );
                        }
                        let error = if outcome.status.is_success() {
                            None
                        } else {
                            Some(format!("{:?}", outcome.status))
                        };
                        if let Ok(mut queue) = outcomes.try_borrow_mut() {
                            queue.push_back((lookup, addrs, error));
                        }
                    });
            match submitted {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    for handle in &handles {
                        drop(self.dns.resolver.cancel_query(*handle));
                    }
                    self.dns_waiters.remove(&lookup);
                    return Err(Error::Dns(error));
                }
            }
        }
        if let Err(error) = self.dns.flush(proactor) {
            // The queries are already submitted; leaving them unflushed would
            // keep the waiter alive after `connect` reports the failure.
            for handle in &handles {
                drop(self.dns.resolver.cancel_query(*handle));
            }
            self.dns_waiters.remove(&lookup);
            return Err(Error::Dns(error));
        }
        Ok(())
    }
    fn begin_connect(
        &mut self,
        proactor: &mut Proactor,
        id: WebSocketSessionId,
        addr: SocketAddr,
    ) -> Result<()> {
        let Some(mut owned) = self.sessions.remove(&id) else {
            return Ok(());
        };
        let fd = match open_socket(&addr) {
            Ok(fd) => fd,
            Err(error) => {
                self.sessions.insert(id, owned);
                return Err(error);
            }
        };
        let peer = Box::new(PeerAddr::new(addr));
        let (ptr, len) = peer.raw();
        let op = operation_id(self.config.net_subsystem, TAG_CONNECT, id);
        if let Err(error) = proactor.prepare_sqe_with(op, |sqe| {
            // SAFETY: `peer` is boxed in the session and neither moved nor
            // dropped until this connect's final CQE, so the kernel reads an
            // initialized `sockaddr`; the descriptor stays open until the
            // io_uring close staged after every operation completes.
            unsafe { net::prep_connect(sqe, fd, ptr, len) }
        }) {
            close_raw(fd);
            self.sessions.insert(id, owned);
            return Err(Error::from(error));
        }
        owned.fd = fd;
        owned.peer = Some(peer);
        owned.connect_op = Some(op);
        owned.inflight += 1;
        owned.phase = SessionPhase::Connecting;
        // A missing deadline must not lose the staged connect, so failure to
        // arm the timer only leaves the session without a connect timeout.
        if let Ok(timeout) = Timeout::new(self.config.connect_timeout) {
            let timer_op = operation_id(self.config.net_subsystem, TAG_CONNECT_TIMEOUT, id);
            let staged = proactor.prepare_sqe_with(timer_op, |sqe| {
                // SAFETY: The `Timeout` owner stays in `session.timer` until
                // its own final CQE, including after cancellation, so the
                // kernel reads live boxed timespec storage.
                unsafe { timeout.prepare(sqe) }
            });
            if staged.is_ok() {
                owned.timer = Some(timeout);
                owned.timer_op = Some(timer_op);
                owned.inflight += 1;
            }
        }
        self.sessions.insert(id, owned);
        Ok(())
    }
}

impl CompletionDispatcher for WebSocketClient {
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        if !crate::dispatch::CompletionRoute::accepts(self, completion.operation_id.subsystem_id())
        {
            return Err(liburing::UringError::InvalidSubsystemId(
                completion.operation_id.subsystem_id().raw(),
            ));
        }
        self.on_completion(completion, submissions)
            .map_err(|_| liburing::UringError::InvalidConfig("WebSocket completion failure"))
    }
}
impl crate::dispatch::CompletionRoute for WebSocketClient {
    fn accepts(&self, subsystem: SubsystemId) -> bool {
        subsystem == self.config.net_subsystem || subsystem == self.config.dns_subsystem
    }
}

#[cfg(test)]
mod tests {
    use super::{driver::decode_op, *};

    #[test]
    fn completion_payloads_round_trip_session_ids() {
        let subsystem = SubsystemId::new_unchecked(2);
        let largest = WebSocketSessionId::new((1_u64 << 52) - 1);
        let op = operation_id(subsystem, TAG_PING_TIMEOUT, largest);
        assert_eq!(op.subsystem_id(), subsystem);
        assert_eq!(decode_op(op.payload()), (TAG_PING_TIMEOUT, largest.raw()));

        let allocated = WebSocketSessionId::new(0x0000_00FF_FFFF_FFFF);
        let recv = operation_id(subsystem, TAG_RECV, allocated);
        assert_eq!(decode_op(recv.payload()).1, allocated.raw());
    }
}
