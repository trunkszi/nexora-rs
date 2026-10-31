//! Non-blocking HTTP client driver: request admission, origin pooling, DNS coalescing,
//! redirects, cancellation, and exactly-once terminal callbacks.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use cares::ResolverOptions;
use liburing::{CompletionDispatcher, Proactor, SubsystemId, ops::Timeout};
use nexora_proto::{Request, Response};

mod config;
mod connect;
mod driver;
mod shutdown;

pub use config::{ClientBuilder, ClientConfig};

use crate::{
    client::connect::DnsProgress,
    dns::HostResolver,
    error::{Error, Result},
    inbox::{
        ClientContext, InboxCommand, RequestId, ResponseCallback, SubmitCommand, SubsystemInbox,
        TimerCallback, TimerCommand, TimerId,
    },
    pool::{
        ConnKind, Connection, OpKind, OriginKey, OriginPool, OriginState, WaiterRemoval,
        next_token, operation_id, stage_cancel, stage_recv, stage_send,
    },
};

struct PendingRequest {
    request: Request,
    origin: OriginKey,
    redirects: usize,
    callback: Option<ResponseCallback>,
    phase: Phase,
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Queued,
    Http1(u64),
    Http2(u64, u32),
}

enum TimerKind {
    User(TimerId),
    Request(RequestId),
    Connect(u64),
}

struct TimerEntry {
    kind: TimerKind,
    _timeout: Box<Timeout>,
    on_expire: Option<TimerCallback>,
}

enum Intent {
    Abort(RequestId, Error),
    FailConnection(u64, Error),
    Retry(OriginKey, i32),
}

/// A submission that could not be admitted, returned with its callback so the
/// caller decides whether the terminal error is reported or delivered.
struct AdmitFailure {
    error: Error,
    callback: Option<ResponseCallback>,
}

/// A non-blocking HTTP/1.1 and HTTP/2 client driven by one [`Proactor`].
pub struct HttpClient {
    config: ClientConfig,
    pool: OriginPool,
    resolver: HostResolver,
    dns: HashMap<OriginKey, DnsProgress>,
    origin_ips: HashMap<OriginKey, Vec<SocketAddr>>,
    requests: HashMap<RequestId, PendingRequest>,
    conns: HashMap<u64, Connection>,
    ops: HashMap<u64, OpKind>,
    timers: HashMap<u64, TimerEntry>,
    inbox: SubsystemInbox,
    intents: VecDeque<Intent>,
    /// Connections that received `GOAWAY`; existing streams drain, new requests
    /// route to a replacement connection instead.
    draining: HashSet<u64>,
    next_conn: u64,
    shutting_down: bool,
    cancelling: HashSet<u64>,
}

impl HttpClient {
    /// Creates a client and arms its non-blocking resolver on `proactor`.
    ///
    /// # Errors
    /// Returns an error when the network and DNS subsystems are the same or
    /// reserved, or a DNS resolver, server-list, or proactor submission error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(proactor: &mut Proactor, config: ClientConfig) -> Result<Self> {
        if config.net_subsystem == SubsystemId::INTERNAL
            || config.dns_subsystem == SubsystemId::INTERNAL
            || config.net_subsystem == config.dns_subsystem
        {
            return Err(Error::InvalidState(String::from(
                "network and DNS subsystems must be distinct non-internal identifiers",
            )));
        }
        let resolver = match config.dns_servers_csv.as_deref() {
            Some(servers) => HostResolver::new(
                config.dns_subsystem,
                ResolverOptions::builder().build()?,
                servers,
                64,
            )?,
            None => HostResolver::default_resolver(config.dns_subsystem)?,
        };
        let mut resolver = resolver;
        resolver.flush(proactor)?;
        let pool = OriginPool::new(config.pool.clone());
        Ok(Self {
            config,
            pool,
            resolver,
            dns: HashMap::new(),
            origin_ips: HashMap::new(),
            requests: HashMap::new(),
            conns: HashMap::new(),
            ops: HashMap::new(),
            timers: HashMap::new(),
            inbox: SubsystemInbox::new(),
            intents: VecDeque::new(),
            draining: HashSet::new(),
            next_conn: 1,
            shutting_down: false,
            cancelling: HashSet::new(),
        })
    }

    /// Returns a builder over the default configuration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Pins `host:port` to the supplied addresses, bypassing DNS.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn resolve_host(&mut self, host: impl Into<String>, port: u16, ips: Vec<IpAddr>) {
        self.resolver.resolve_host(host, port, ips);
    }

    /// Submits a request and registers its terminal callback.
    ///
    /// Returns only after the request owns a slot in the client, so the
    /// callback is guaranteed to fire exactly once even when it completes
    /// during a later turn.
    ///
    /// # Errors
    /// Returns an error when the request timer or an immediately reusable
    /// connection's socket operation cannot be prepared.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn submit<F>(
        &mut self,
        proactor: &mut Proactor,
        request: Request,
        on_complete: F,
    ) -> Result<RequestId>
    where
        F: FnOnce(&mut ClientContext, RequestId, Result<Response>) + 'static,
    {
        let id = self.inbox.next_request_id();
        match self.admit(proactor, id, request, Box::new(on_complete)) {
            Ok(()) => Ok(id),
            // No identifier was handed out, so `submit` reports the failure
            // instead of invoking a callback for a request the caller does not
            // know about.
            Err(failure) => Err(failure.error),
        }
    }

    /// Cancels an in-flight request, invoking its callback with [`Error::Cancelled`].
    ///
    /// Returns `false` when the request already reached a terminal state.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn cancel(&mut self, proactor: &mut Proactor, request_id: RequestId) -> bool {
        self.abort(proactor, request_id, Error::Cancelled)
    }

    /// Schedules a user timer delivered through [`ClientContext`].
    ///
    /// # Errors
    /// Returns an error when the timeout operand or its SQE cannot be prepared.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_timer<F>(
        &mut self,
        proactor: &mut Proactor,
        delay: Duration,
        on_expire: F,
    ) -> Result<TimerId>
    where
        F: FnOnce(&mut ClientContext, TimerId) + 'static,
    {
        let id = self.inbox.next_timer_id();
        match self.arm_timer(
            proactor,
            delay,
            TimerKind::User(id),
            Some(Box::new(on_expire)),
        ) {
            Ok(()) => Ok(id),
            Err((error, _callback)) => Err(error),
        }
    }

    /// Advances DNS, socket, timer, and callback work by one turn.
    ///
    /// Returns the number of completions dispatched.
    ///
    /// # Errors
    /// Returns a DNS or proactor submission/dispatch error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn drive(&mut self, proactor: &mut Proactor) -> Result<usize> {
        self.drive_with(proactor, &mut crate::dispatch::RejectForeign)
    }

    /// Advances this client and routes other subsystems through `peer`.
    /// # Errors
    /// Returns DNS, submission, or dispatch errors. Unknown routes fail closed.
    /// # Panics
    /// User callbacks may panic.
    pub fn drive_with<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        proactor: &mut Proactor,
        peer: &mut D,
    ) -> Result<usize> {
        self.step(proactor)?;
        let mut dispatch =
            |completion: liburing::Completion,
             submissions: &mut liburing::SubmissionContext<'_>| {
                if crate::dispatch::CompletionRoute::accepts(
                    self,
                    completion.operation_id.subsystem_id(),
                ) {
                    CompletionDispatcher::dispatch(self, completion, submissions)
                } else {
                    peer.dispatch(completion, submissions)
                }
            };
        let count = proactor.tick(&mut dispatch)?;
        self.step(proactor)?;
        proactor.submit()?;
        Ok(count)
    }

    /// Returns the number of requests that have not reached a terminal state.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn active_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Returns the number of idle connections for one origin.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn idle_connection_count(&self, origin: &OriginKey) -> usize {
        self.pool.idle_count(origin)
    }

    fn step(&mut self, proactor: &mut Proactor) -> Result<()> {
        if self.shutting_down {
            return self.flush_shutdown(proactor);
        }
        self.drain_commands(proactor)?;
        self.apply_intents(proactor)?;
        for (_, connection) in self.pool.expired(Instant::now()) {
            // The pool reports only connections without a live exchange or
            // stream, so every reported token is safe to close.
            if let Some(conn) = self.conns.get_mut(&connection) {
                conn.want_close = true;
            }
        }
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            self.flush_connection(proactor, id)?;
        }
        let queued: Vec<RequestId> = self
            .requests
            .iter()
            .filter(|(_, entry)| matches!(entry.phase, Phase::Queued))
            .map(|(id, _)| *id)
            .collect();
        for id in queued {
            self.route(proactor, id)?;
        }
        self.resolver.flush(proactor)
    }

    fn admit(
        &mut self,
        proactor: &mut Proactor,
        id: RequestId,
        mut request: Request,
        callback: ResponseCallback,
    ) -> std::result::Result<(), AdmitFailure> {
        if self.shutting_down {
            return Err(AdmitFailure {
                error: Error::ConnectionClosed,
                callback: Some(callback),
            });
        }
        let key = OriginKey::from_uri(&request.uri);
        if !request.headers.contains("host") {
            let authority = request.uri.authority();
            request.headers.insert("host", authority);
        }
        self.pool.push_waiter(&key, id);
        self.requests.insert(
            id,
            PendingRequest {
                request,
                origin: key.clone(),
                redirects: 0,
                callback: Some(callback),
                phase: Phase::Queued,
            },
        );
        if let Err((error, _callback)) = self.arm_timer(
            proactor,
            self.config.request_timeout,
            TimerKind::Request(id),
            None,
        ) {
            return Err(self.reject(id, &key, error));
        }
        if let Err(error) = self.route(proactor, id) {
            return Err(self.reject(id, &key, error));
        }
        Ok(())
    }

    /// Removes a request whose admission failed and returns its callback.
    ///
    /// A rejected request is the last waiter often enough (the triggering
    /// submission is frequently alone) that it must release the origin exactly
    /// like [`Self::abort`] does, including the shared DNS query.
    fn reject(&mut self, id: RequestId, key: &OriginKey, error: Error) -> AdmitFailure {
        let callback = self.requests.remove(&id).and_then(|entry| entry.callback);
        if self.pool.remove_waiter(key, id) == WaiterRemoval::RemovedLast {
            let handles = self.pool.take_query_handles(key);
            self.resolver.cancel_queries(&handles);
            drop(self.dns.remove(key));
            self.pool.set_state(key, OriginState::Idle);
        }
        AdmitFailure { error, callback }
    }

    fn route(&mut self, proactor: &mut Proactor, id: RequestId) -> Result<()> {
        let Some(key) = self.requests.get(&id).map(|entry| entry.origin.clone()) else {
            return Ok(());
        };
        match self.pool.state(&key).unwrap_or(OriginState::Idle) {
            OriginState::ReadyHttp1 => {
                let idle = self.conns.values().find(|conn| {
                    conn.kind == ConnKind::Http1
                        && conn.current.is_none()
                        && !conn.want_close
                        && conn.key == key
                });
                if let Some(conn) = idle.map(|conn| conn.id) {
                    self.pool.remove_waiter(&key, id);
                    return self.dispatch(proactor, conn, id, ConnKind::Http1);
                }
                if self.pool.connection_count(&key) < self.config.pool.max_connections_per_origin {
                    // Keep the waiter queued: the handshake that just started
                    // takes it, and parallel connections fan out to the limit.
                    return self.open_connection(proactor, &key);
                }
                self.pool.push_waiter(&key, id);
                Ok(())
            }
            OriginState::ReadyHttp2 => {
                let usable = self.conns.values().find(|conn| {
                    conn.kind == ConnKind::Http2
                        && !conn.want_close
                        && !self.draining.contains(&conn.id)
                        && conn.key == key
                        && conn
                            .http2
                            .as_ref()
                            .is_some_and(|http2| http2.can_open_stream())
                });
                if let Some(conn) = usable.map(|conn| conn.id) {
                    self.pool.remove_waiter(&key, id);
                    return self.dispatch(proactor, conn, id, ConnKind::Http2);
                }
                if self.live_state(&key) == Some(OriginState::ReadyHttp2) {
                    // Every connection is at its stream limit; a stream
                    // completion re-routes this waiter on a later turn.
                    self.pool.push_waiter(&key, id);
                    return Ok(());
                }
                // No multiplexed connection remains (for example after
                // GOAWAY), so the origin needs a replacement connection.
                self.open_connection(proactor, &key)
            }
            OriginState::Idle | OriginState::Closed => {
                if self.has_connecting(&key) {
                    self.pool.push_waiter(&key, id);
                    return Ok(());
                }
                self.start_origin(proactor, &key)
            }
            _ => {
                self.pool.push_waiter(&key, id);
                Ok(())
            }
        }
    }

    fn dispatch(
        &mut self,
        proactor: &mut Proactor,
        conn: u64,
        id: RequestId,
        kind: ConnKind,
    ) -> Result<()> {
        let Some((request, key)) = self
            .requests
            .get(&id)
            .map(|entry| (entry.request.clone(), entry.origin.clone()))
        else {
            return Ok(());
        };
        if request.body.len() > self.config.max_request_body_size {
            self.intents.push_back(Intent::Abort(
                id,
                Error::BodyTooLarge {
                    size: request.body.len(),
                    max: self.config.max_request_body_size,
                },
            ));
            return Ok(());
        }
        let mut stream = None;
        let encoded = match self.conns.get_mut(&conn) {
            Some(connection) if kind == ConnKind::Http1 => connection
                .h1
                .encode_request(&request, &mut connection.out)
                .and_then(|()| connection.pump()),
            Some(connection) => match connection.http2.as_mut() {
                Some(http2) => http2
                    .submit_request(&request)
                    .map(|value| stream = Some(value)),
                None => return Ok(()),
            },
            None => return Ok(()),
        };
        if let Err(error) = encoded {
            // Both codecs reject a message before writing a frame, so the
            // connection (and its sibling streams) stays usable.
            self.intents
                .push_back(Intent::Abort(id, Error::Proto(error)));
            return Ok(());
        }
        let mut drained = Ok(());
        if let Some(connection) = self.conns.get_mut(&conn) {
            match stream {
                Some(value) => {
                    connection.streams.insert(value, id);
                    drained = connection.drain_http2();
                }
                None => connection.current = Some(id),
            }
        } else {
            return Ok(());
        }
        if let Some(entry) = self.requests.get_mut(&id) {
            entry.phase = match stream {
                Some(value) => Phase::Http2(conn, value),
                None => Phase::Http1(conn),
            };
        }
        self.pool.mark_busy(&key, conn);
        if let Err(error) = drained {
            // The stream is registered, so the deferred abort queues
            // RST_STREAM (CANCEL) and releases it; siblings keep running.
            self.intents
                .push_back(Intent::Abort(id, Error::Proto(error)));
            return Ok(());
        }
        // Socket staging is retried by the flush pass; a failure here must not
        // leave a request recorded as in flight with no owner.
        drop(self.flush_connection(proactor, conn));
        Ok(())
    }

    fn flush_connection(&mut self, proactor: &mut Proactor, id: u64) -> Result<()> {
        let Some(conn) = self.conns.get_mut(&id) else {
            return Ok(());
        };
        if conn.want_close && conn.close_op.is_none() {
            // `Connection::flush` defers the close until every submitted
            // operation completes. An idle keep-alive receive never completes
            // on its own, so retiring a connection means cancelling the work
            // that would otherwise hold its descriptor open indefinitely.
            let targets = [conn.rx_op, conn.send_op, conn.connect_op];
            for target in targets.into_iter().flatten() {
                let token = target.payload().raw();
                if !self.cancelling.contains(&token) {
                    stage_cancel(proactor, self.config.net_subsystem, target)?;
                    let _inserted = self.cancelling.insert(token);
                }
            }
        }
        conn.flush(proactor, self.config.net_subsystem, &mut self.ops)?;
        if self.draining.contains(&id)
            && conn.streams.is_empty()
            && conn.tx_pending.is_empty()
            && conn.tx_inflight.is_empty()
        {
            conn.want_close = true;
        }
        // `Connection::flush` stages socket work only once a connection is
        // established; the TLS handshake needs the same receive/send loop.
        if conn.kind == ConnKind::Handshaking && conn.close_op.is_none() && !conn.want_close {
            if conn.rx_op.is_none() {
                stage_recv(proactor, self.config.net_subsystem, &mut self.ops, conn)?;
            }
            if conn.send_op.is_none()
                && !(conn.tx_pending.is_empty() && conn.tx_inflight.is_empty())
            {
                stage_send(proactor, self.config.net_subsystem, &mut self.ops, conn)?;
            }
        }
        Ok(())
    }

    fn abort(&mut self, proactor: &mut Proactor, id: RequestId, error: Error) -> bool {
        let Some(entry) = self.requests.remove(&id) else {
            return false;
        };
        match entry.phase {
            Phase::Queued => {
                if self.pool.remove_waiter(&entry.origin, id) == WaiterRemoval::RemovedLast {
                    let handles = self.pool.take_query_handles(&entry.origin);
                    self.resolver.cancel_queries(&handles);
                    drop(self.dns.remove(&entry.origin));
                    self.pool.set_state(&entry.origin, OriginState::Idle);
                }
            }
            Phase::Http1(conn) => {
                let (rx, send) = match self.conns.get_mut(&conn) {
                    Some(connection) => {
                        connection.current = None;
                        connection.want_close = true;
                        (connection.rx_op, connection.send_op)
                    }
                    None => (None, None),
                };
                self.pool.remove_connection(&entry.origin, conn);
                for target in [rx, send].into_iter().flatten() {
                    if stage_cancel(proactor, self.config.net_subsystem, target).is_ok() {
                        let _inserted = self.cancelling.insert(target.payload().raw());
                    }
                }
            }
            Phase::Http2(conn, stream) => {
                if let Some(connection) = self.conns.get_mut(&conn) {
                    if let Some(http2) = connection.http2.as_mut() {
                        drop(http2.cancel_stream(stream));
                    }
                    let _removed = connection.streams.remove(&stream);
                    drop(connection.drain_http2());
                }
                self.release_stream(conn);
            }
        }
        if let Some(callback) = entry.callback {
            let mut ctx = self.inbox.context();
            callback(&mut ctx, id, Err(error));
        }
        true
    }

    fn apply_intents(&mut self, proactor: &mut Proactor) -> Result<()> {
        while let Some(intent) = self.intents.pop_front() {
            match intent {
                Intent::Abort(id, error) => drop(self.abort(proactor, id, error)),
                Intent::FailConnection(id, error) => self.fail_connection(id, error),
                Intent::Retry(key, errno) => {
                    let more = self
                        .pool
                        .entry_ref(&key)
                        .is_some_and(|entry| !entry.candidate_ips.is_empty());
                    if more {
                        self.open_connection(proactor, &key)?;
                    } else if self.dns.get(&key).is_some_and(DnsProgress::is_pending)
                        || self.live_state(&key).is_some()
                    {
                        // Another address family or a pooled connection can
                        // still serve the waiters, which stay queued.
                    } else {
                        self.fail_origin(&key, Error::Io(std::io::Error::from_raw_os_error(errno)));
                    }
                }
            }
        }
        Ok(())
    }

    fn drain_commands(&mut self, proactor: &mut Proactor) -> Result<()> {
        while let Some(command) = self.inbox.pop() {
            match command {
                InboxCommand::Submit(SubmitCommand {
                    request_id,
                    request,
                    callback,
                }) => {
                    if let Err(AdmitFailure { error, callback }) =
                        self.admit(proactor, request_id, request, callback)
                    {
                        self.deliver(request_id, callback, error);
                    }
                }
                InboxCommand::Cancel(id) => drop(self.abort(proactor, id, Error::Cancelled)),
                InboxCommand::SetTimer(TimerCommand {
                    timer_id,
                    delay,
                    callback,
                }) => {
                    if let Err((error, callback)) =
                        self.arm_timer(proactor, delay, TimerKind::User(timer_id), Some(callback))
                    {
                        // `ClientContext::set_timer` cannot report a failure,
                        // so a timer that could not be armed fires now rather
                        // than never.
                        if let Some(callback) = callback {
                            let mut ctx = self.inbox.context();
                            callback(&mut ctx, timer_id);
                        }
                        drop(error);
                    }
                }
                InboxCommand::DnsResolved(resolution) => self.apply_dns(proactor, resolution),
                // Deferred server replies and WebSocket commands belong to the
                // server and WebSocket drivers, which own their own inboxes.
                InboxCommand::Respond(_)
                | InboxCommand::WebSocketSend { .. }
                | InboxCommand::WebSocketClose { .. } => {}
            }
        }
        Ok(())
    }

    /// Delivers a terminal error for a request that never reached a connection.
    fn deliver(&mut self, id: RequestId, callback: Option<ResponseCallback>, error: Error) {
        if let Some(callback) = callback {
            let mut ctx = self.inbox.context();
            callback(&mut ctx, id, Err(error));
        }
    }

    fn arm_timer(
        &mut self,
        proactor: &mut Proactor,
        delay: Duration,
        kind: TimerKind,
        on_expire: Option<TimerCallback>,
    ) -> std::result::Result<(), (Error, Option<TimerCallback>)> {
        if self.shutting_down {
            return Err((Error::ConnectionClosed, on_expire));
        }
        let timeout = match Timeout::new(delay) {
            Ok(timeout) => Box::new(timeout),
            Err(error) => return Err((Error::Uring(error), on_expire)),
        };
        let token = next_token();
        let id = match operation_id(self.config.net_subsystem, token) {
            Ok(id) => id,
            Err(error) => return Err((error, on_expire)),
        };
        // SAFETY: The boxed timespec is retained in `self.timers` until its final
        // timeout CQE, and boxing keeps its address stable while the map moves.
        if let Err(error) = proactor.prepare_sqe_with(id, |sqe| unsafe { timeout.prepare(sqe) }) {
            return Err((Error::Uring(error), on_expire));
        }
        self.ops.insert(token, OpKind::Timer(token));
        self.timers.insert(
            token,
            TimerEntry {
                kind,
                _timeout: timeout,
                on_expire,
            },
        );
        Ok(())
    }
}
