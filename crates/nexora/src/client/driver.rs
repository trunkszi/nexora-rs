//! Completion handlers for the HTTP client driver.
//!
//! These handlers only mutate connection and request state. Socket work is
//! staged later by `HttpClient::flush_connection` and the DNS resolver's own
//! flush pass, so no handler needs a proactor borrow.

use std::time::Instant;

use liburing::Completion;
use nexora_proto::{
    AlpnProtocol, Http1KeepAlive, Http2Connection, Http2Event, Http2Role, Method, ProtoError,
    Request, Response, TlsSession,
};

use super::{HttpClient, Intent, Phase, TimerKind, connect::http2_config};
use crate::{
    error::{Error, Result},
    inbox::RequestId,
    pool::{ConnKind, IngestOutcome, OpKind, OriginKey, OriginState},
};

impl HttpClient {
    pub(super) fn on_completion(&mut self, completion: Completion) {
        let token = completion.operation_id.payload().raw();
        let _removed = self.cancelling.remove(&token);
        let Some(kind) = self.ops.remove(&token) else {
            return;
        };
        match kind {
            OpKind::Connect(id) => self.on_connect(id, completion.result),
            OpKind::Recv(id) => self.on_recv(id, completion.result),
            OpKind::Send(id) => self.on_send(id, completion.result),
            OpKind::Close(id) => {
                let _removed = self.draining.remove(&id);
                if let Some(conn) = self.conns.remove(&id) {
                    self.pool.remove_connection(&conn.key, id);
                    if self.pool.connection_count(&conn.key) == 0 {
                        self.pool.set_state(&conn.key, OriginState::Idle);
                    }
                }
            }
            OpKind::Timer(id) => self.on_timer(id),
        }
    }

    fn on_connect(&mut self, id: u64, result: i32) {
        let state = self.conns.get_mut(&id).map(|conn| {
            conn.connect_op = None;
            conn.in_flight_ops = conn.in_flight_ops.saturating_sub(1);
            (conn.key.clone(), conn.kind, conn.want_close)
        });
        let Some((key, kind, closing)) = state else {
            return;
        };
        if kind == ConnKind::Closed || closing {
            // The driver already retired this connection, for example on its
            // connect deadline or an idle eviction; a late CQE must not set it
            // up again or retry a descriptor that is being closed.
            return;
        }
        if result < 0 {
            if let Some(conn) = self.conns.get_mut(&id) {
                conn.want_close = true;
            }
            self.pool.remove_connection(&key, id);
            self.intents.push_back(Intent::Retry(key, -result));
            return;
        }
        let tls_config = self.config.tls_config.clone();
        let http2_settings = http2_config(&self.config);
        let failure;
        let mut ready = false;
        {
            let Some(conn) = self.conns.get_mut(&id) else {
                return;
            };
            if conn.key.scheme.is_tls() {
                let mut config = tls_config.unwrap_or_default();
                if !self.config.prefer_http2 {
                    config = config.with_alpn(&[AlpnProtocol::Http11]);
                }
                let server_name = self
                    .config
                    .tls_server_name
                    .as_deref()
                    .unwrap_or(&conn.key.host);
                match TlsSession::new_client(&config, server_name) {
                    Ok(session) => {
                        conn.tls = Some(session);
                        conn.kind = ConnKind::Handshaking;
                        failure = conn.pump().err().map(Error::Proto);
                    }
                    Err(error) => failure = Some(Error::Proto(error)),
                }
            } else {
                if conn.http2.is_some() {
                    conn.http2 = Some(Http2Connection::new(Http2Role::Client, http2_settings));
                }
                conn.kind = if conn.http2.is_some() {
                    ConnKind::Http2
                } else {
                    ConnKind::Http1
                };
                failure = if conn.http2.is_some() {
                    conn.drain_http2().err().map(Error::Proto)
                } else {
                    None
                };
                ready = true;
            }
        }
        match failure {
            Some(error) => self.fail_connection(id, error),
            None if ready => self.mark_ready(id),
            None => {
                self.pool.set_state(&key, OriginState::Handshaking);
            }
        }
    }

    fn mark_ready(&mut self, id: u64) {
        if let Some(conn) = self.conns.get(&id) {
            let state = if conn.kind == ConnKind::Http2 {
                OriginState::ReadyHttp2
            } else {
                OriginState::ReadyHttp1
            };
            let key = conn.key.clone();
            self.pool.set_state(&key, state);
        }
    }

    fn on_recv(&mut self, id: u64, result: i32) {
        {
            let Some(conn) = self.conns.get_mut(&id) else {
                return;
            };
            conn.rx_op = None;
            conn.in_flight_ops = conn.in_flight_ops.saturating_sub(1);
        }
        if result <= 0 {
            let error = if result == 0 {
                Error::ConnectionClosed
            } else {
                Error::Io(std::io::Error::from_raw_os_error(-result))
            };
            self.fail_connection(id, error);
            return;
        }
        let outcome = match self.conns.get_mut(&id) {
            Some(conn) => conn.ingest(result as usize),
            None => return,
        };
        match outcome {
            IngestOutcome::Failed(error) => {
                self.fail_connection(id, Error::Proto(error));
                return;
            }
            IngestOutcome::Ready(alpn) => self.tls_ready(id, alpn),
            IngestOutcome::NeedMore => {}
        }
        self.process(id);
    }

    fn on_send(&mut self, id: u64, result: i32) {
        let failed;
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.send_op = None;
            conn.in_flight_ops = conn.in_flight_ops.saturating_sub(1);
            failed = result < 0;
            if !failed {
                let sent = (result as usize).min(conn.tx_inflight.len());
                if sent < conn.tx_inflight.len() {
                    drop(conn.tx_inflight.split_to(sent));
                } else {
                    conn.tx_inflight.clear();
                }
            }
        } else {
            return;
        }
        if failed {
            self.fail_connection(id, Error::Io(std::io::Error::from_raw_os_error(-result)));
        }
    }

    fn on_timer(&mut self, token: u64) {
        let Some(entry) = self.timers.remove(&token) else {
            return;
        };
        if self.shutting_down {
            return;
        }
        match entry.kind {
            TimerKind::User(id) => {
                if let Some(callback) = entry.on_expire {
                    let mut ctx = self.inbox.context();
                    callback(&mut ctx, id);
                }
            }
            TimerKind::Request(id) => self.intents.push_back(Intent::Abort(id, Error::Timeout)),
            TimerKind::Connect(id) => {
                let establishing = self.conns.get(&id).is_some_and(|conn| {
                    matches!(conn.kind, ConnKind::Connecting | ConnKind::Handshaking)
                });
                if establishing {
                    self.intents
                        .push_back(Intent::FailConnection(id, Error::Timeout));
                }
            }
        }
    }

    fn tls_ready(&mut self, id: u64, alpn: Option<AlpnProtocol>) {
        let http2_settings = http2_config(&self.config);
        let failure = match self.conns.get_mut(&id) {
            Some(conn) if alpn == Some(AlpnProtocol::Http2) => {
                conn.http2 = Some(Http2Connection::new(Http2Role::Client, http2_settings));
                conn.kind = ConnKind::Http2;
                conn.drain_http2().err().map(Error::Proto)
            }
            Some(_)
                if self
                    .config
                    .tls_config
                    .as_ref()
                    .is_some_and(|cfg| !cfg.allows_http11()) =>
            {
                Some(Error::Proto(ProtoError::Tls(String::from(
                    "peer did not negotiate HTTP/2 ALPN",
                ))))
            }
            Some(conn) => {
                conn.http2 = None;
                conn.kind = ConnKind::Http1;
                None
            }
            None => return,
        };
        match failure {
            Some(error) => self.fail_connection(id, error),
            None => self.mark_ready(id),
        }
    }

    fn process(&mut self, id: u64) {
        let Some((kind, current)) = self.conns.get(&id).map(|conn| (conn.kind, conn.current))
        else {
            return;
        };
        if kind == ConnKind::Http1 {
            let Some(request_id) = current else { return };
            let method = self
                .requests
                .get(&request_id)
                .map_or(Method::Get, |entry| entry.request.method);
            let decoded = loop {
                let step = match self.conns.get_mut(&id) {
                    Some(conn) => conn.h1.decode_response(&mut conn.plain, method),
                    None => return,
                };
                match step {
                    Ok(Some((response, keep_alive)))
                        if response.status.is_informational()
                            && keep_alive != Http1KeepAlive::Upgrade =>
                    {
                        // `100 Continue` and `103 Early Hints` precede the
                        // final response and are not terminal.
                        continue;
                    }
                    other => break other,
                }
            };
            match decoded {
                Ok(Some((response, keep_alive))) => {
                    let trailing = self.conns.get(&id).map_or(0, |conn| conn.plain.len());
                    if let Some(conn) = self.conns.get_mut(&id) {
                        conn.current = None;
                    }
                    if keep_alive == Http1KeepAlive::Upgrade {
                        self.evict_connection(id);
                        if trailing == 0 {
                            self.finish(request_id, response);
                        } else {
                            // The upgrade consumed only the header block; the
                            // bytes after it belong to the new protocol, and
                            // freeing the connection would discard them
                            // silently. This layer has no session to hand them
                            // to, so it reports the loss instead.
                            self.complete(
                                request_id,
                                Err(Error::InvalidState(format!(
                                    "protocol upgrade left {trailing} trailing bytes unclaimed"
                                ))),
                            );
                        }
                        return;
                    }
                    if keep_alive == Http1KeepAlive::KeepAlive {
                        if let Some(key) = self.conns.get(&id).map(|entry| entry.key.clone()) {
                            self.pool.mark_idle(&key, id, Instant::now());
                        }
                    } else {
                        self.evict_connection(id);
                    }
                    self.finish(request_id, response);
                }
                Ok(None) => {}
                Err(error) => self.fail_connection(id, proto_error(error)),
            }
        } else if kind == ConnKind::Http2 {
            let mut events = Vec::new();
            let mut failure = None;
            if let Some(conn) = self.conns.get_mut(&id) {
                if let Some(http2) = conn.http2.as_mut() {
                    failure = http2.feed_bytes(&mut conn.plain).err().map(Error::Proto);
                    if failure.is_none() {
                        while let Some(event) = http2.poll_event() {
                            events.push(event);
                        }
                    }
                }
                if failure.is_none() {
                    failure = conn.drain_http2().err().map(Error::Proto);
                }
            } else {
                return;
            }
            match failure {
                Some(error) => self.fail_connection(id, error),
                None => events
                    .into_iter()
                    .for_each(|event| self.on_http2_event(id, event)),
            }
        }
    }

    fn on_http2_event(&mut self, conn: u64, event: Http2Event) {
        let stream = match &event {
            Http2Event::ResponseReceived { stream_id, .. }
            | Http2Event::StreamReset { stream_id, .. }
            | Http2Event::StreamBodyTooLarge { stream_id, .. } => Some(*stream_id),
            _ => None,
        };
        let Some(stream_id) = stream else {
            if matches!(event, Http2Event::GoAwayReceived { .. }) {
                // GOAWAY stops new streams, not the ones already running:
                // keep them and let routing open a replacement connection.
                self.draining.insert(conn);
            }
            return;
        };
        let Some(id) = self
            .conns
            .get_mut(&conn)
            .and_then(|entry| entry.streams.remove(&stream_id))
        else {
            return;
        };
        match event {
            Http2Event::ResponseReceived { response, .. } => self.finish(id, response),
            Http2Event::StreamReset { error_code, .. } => self.complete(
                id,
                Err(Error::Proto(ProtoError::Http2StreamError {
                    stream_id,
                    code: error_code,
                    reason: String::from("peer reset the stream"),
                })),
            ),
            Http2Event::StreamBodyTooLarge { size, max, .. } => {
                self.complete(id, Err(Error::BodyTooLarge { size, max }));
            }
            _ => {}
        }
        self.release_stream(conn);
    }

    pub(super) fn release_stream(&mut self, conn: u64) {
        let Some(entry) = self.conns.get(&conn) else {
            return;
        };
        if entry.streams.is_empty() {
            let key = entry.key.clone();
            self.pool.mark_idle(&key, conn, Instant::now());
        }
    }

    /// Marks a connection unusable and unregisters it from its origin.
    fn evict_connection(&mut self, id: u64) {
        let key = self.conns.get(&id).map(|conn| conn.key.clone());
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.want_close = true;
        }
        if let Some(key) = key {
            self.pool.remove_connection(&key, id);
        }
        let _removed = self.draining.remove(&id);
    }

    fn finish(&mut self, id: RequestId, response: Response) {
        let Some(entry) = self.requests.get(&id) else {
            return;
        };
        let status = response.status.as_u16();
        let location = response.header("location").map(str::to_owned);
        let redirects = entry.redirects;
        let follows = self.config.follow_redirects && is_redirect(status) && location.is_some();
        if !follows {
            self.complete(id, Ok(response));
            return;
        }
        if redirects >= self.config.max_redirects {
            self.complete(
                id,
                Err(Error::TooManyRedirects {
                    max: self.config.max_redirects,
                }),
            );
            return;
        }
        let Some(location) = location else {
            self.complete(id, Ok(response));
            return;
        };
        let next = self
            .requests
            .get(&id)
            .and_then(|entry| redirect_follow_up(&entry.request, status, &location));
        let Some(next) = next else {
            self.complete(id, Err(Error::InvalidUri(location)));
            return;
        };
        let Some(entry) = self.requests.get_mut(&id) else {
            return;
        };
        entry.request = next;
        entry.redirects = entry.redirects.saturating_add(1);
        entry.origin = OriginKey::from_uri(&entry.request.uri);
        entry.phase = Phase::Queued;
        let origin = entry.origin.clone();
        // The queued pass of the next turn routes the follow-up request.
        self.pool.push_waiter(&origin, id);
    }

    pub(super) fn complete(&mut self, id: RequestId, outcome: Result<Response>) {
        if let Some(entry) = self.requests.remove(&id)
            && let Some(callback) = entry.callback
        {
            let mut ctx = self.inbox.context();
            callback(&mut ctx, id, outcome);
        }
    }

    pub(super) fn fail_connection(&mut self, id: u64, error: Error) {
        let _removed = self.draining.remove(&id);
        let (key, current, streams, establishing) = match self.conns.get_mut(&id) {
            Some(conn) => {
                let establishing =
                    matches!(conn.kind, ConnKind::Connecting | ConnKind::Handshaking);
                conn.kind = ConnKind::Closed;
                conn.want_close = true;
                (
                    conn.key.clone(),
                    conn.current.take(),
                    conn.streams.drain().map(|(_, id)| id).collect::<Vec<_>>(),
                    establishing,
                )
            }
            None => return,
        };
        self.pool.remove_connection(&key, id);
        if self.pool.connection_count(&key) == 0 {
            self.pool.set_state(&key, OriginState::Idle);
        }
        // A codec failure terminates every active stream with its original cause.
        for request in streams {
            let cause = match &error {
                Error::Proto(cause) => Error::Proto(cause.clone()),
                _ => Error::ConnectionClosed,
            };
            self.complete(request, Err(cause));
        }
        if let Some(request) = current {
            self.complete(request, Err(error));
        } else if establishing {
            self.fail_origin(&key, error);
        }
    }
}

/// Maps codec limit violations onto the dedicated client error variants.
fn proto_error(error: ProtoError) -> Error {
    match error {
        ProtoError::BodyTooLarge { size, max } => Error::BodyTooLarge { size, max },
        other => Error::Proto(other),
    }
}

impl liburing::CompletionDispatcher for HttpClient {
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut liburing::SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        let subsystem = completion.operation_id.subsystem_id();
        if subsystem == self.config.dns_subsystem {
            return liburing::CompletionDispatcher::dispatch(
                &mut self.resolver,
                completion,
                submissions,
            );
        }
        if subsystem != self.config.net_subsystem {
            return Err(liburing::UringError::InvalidSubsystemId(subsystem.raw()));
        }
        submissions.claim_completion(completion)?;
        self.on_completion(completion);
        Ok(())
    }
}

impl crate::dispatch::CompletionRoute for HttpClient {
    fn accepts(&self, subsystem: liburing::SubsystemId) -> bool {
        subsystem == self.config.net_subsystem || subsystem == self.config.dns_subsystem
    }
}

/// Reports whether `status` is a redirect the client may follow.
pub(super) fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Builds the follow-up request for a redirect, or `None` when `location`
/// cannot be resolved against the previous URI.
pub(super) fn redirect_follow_up(
    previous: &Request,
    status: u16,
    location: &str,
) -> Option<Request> {
    let uri = previous.uri.resolve_redirect(location).ok()?;
    let previous_origin = OriginKey::from_uri(&previous.uri);
    let origin = OriginKey::from_uri(&uri);
    let drop_body =
        status == 303 || (matches!(status, 301 | 302) && previous.method == Method::Post);
    let mut next = Request::new(
        if drop_body {
            Method::Get
        } else {
            previous.method
        },
        uri,
    );
    next.version = previous.version;
    next.headers = previous.headers.clone();
    drop(next.headers.remove("host"));
    // The Host header must name the redirect target: HTTP/1.1 servers route on
    // it and the HTTP/2 codec rejects a host that disagrees with `:authority`.
    let authority = next.uri.authority();
    next.headers.insert("host", authority);
    if drop_body {
        drop(next.headers.remove("content-length"));
        drop(next.headers.remove("transfer-encoding"));
    } else {
        next.body = previous.body.clone();
    }
    if origin != previous_origin {
        // Credentials are scoped to the origin that issued them.
        drop(next.headers.remove("authorization"));
        drop(next.headers.remove("cookie"));
    }
    Some(next)
}

#[cfg(test)]
mod tests {
    use nexora_proto::{Bytes, Uri};

    use super::*;

    fn uri(raw: &str) -> Result<Uri> {
        Ok(Uri::parse(raw)?)
    }

    fn invalid(message: &str) -> Error {
        Error::InvalidState(message.to_string())
    }

    #[test]
    fn redirect_303_turns_a_post_into_a_bodyless_get() -> Result<()> {
        let mut request = Request::new(Method::Post, uri("http://a.test:8080/post")?);
        request.headers.insert("host", "a.test:8080");
        request.headers.insert("content-length", "3");
        request.body = Bytes::from_static(b"abc");
        let next = redirect_follow_up(&request, 303, "/next")
            .ok_or_else(|| invalid("relative redirect did not resolve"))?;
        assert_eq!(next.method, Method::Get);
        assert!(next.body.is_empty());
        assert_eq!(next.uri.host(), "a.test");
        assert_eq!(next.uri.port(), 8080);
        assert_eq!(next.uri.path(), "/next");
        assert_eq!(next.header("host"), Some("a.test:8080"));
        assert_eq!(next.header("content-length"), None);
        assert_eq!(next.header("transfer-encoding"), None);
        Ok(())
    }

    #[test]
    fn redirect_307_keeps_the_body_but_drops_cross_origin_credentials() -> Result<()> {
        let mut request = Request::new(Method::Post, uri("http://a.test/post")?);
        request.headers.insert("host", "a.test");
        request.headers.insert("authorization", "Bearer secret");
        request.headers.insert("cookie", "session=1");
        request.body = Bytes::from_static(b"payload");
        let next = redirect_follow_up(&request, 307, "http://b.test:9000/next")
            .ok_or_else(|| invalid("absolute redirect did not resolve"))?;
        assert_eq!(next.method, Method::Post);
        assert_eq!(next.body.as_slice(), &b"payload"[..]);
        assert_eq!(next.uri.host(), "b.test");
        assert_eq!(next.uri.port(), 9000);
        assert_eq!(next.header("host"), Some("b.test:9000"));
        assert_eq!(next.header("authorization"), None);
        assert_eq!(next.header("cookie"), None);
        Ok(())
    }

    #[test]
    fn redirect_307_keeps_credentials_on_the_same_origin() -> Result<()> {
        let mut request = Request::new(Method::Post, uri("http://a.test/post")?);
        request.headers.insert("host", "a.test");
        request.headers.insert("authorization", "Bearer secret");
        let next = redirect_follow_up(&request, 307, "/again")
            .ok_or_else(|| invalid("relative redirect did not resolve"))?;
        assert_eq!(next.uri.host(), "a.test");
        assert_eq!(next.header("host"), Some("a.test"));
        assert_eq!(next.header("authorization"), Some("Bearer secret"));
        Ok(())
    }

    #[test]
    fn redirect_rejects_a_location_that_does_not_parse() -> Result<()> {
        let request = Request::get("http://a.test/")?;
        assert!(redirect_follow_up(&request, 302, "http://a.test/%zz").is_none());
        Ok(())
    }

    #[test]
    fn only_the_followed_statuses_are_redirects() {
        for status in [301u16, 302, 303, 307, 308] {
            assert!(is_redirect(status), "status {status} must be followed");
        }
        for status in [200u16, 300, 304, 305, 306, 309, 400] {
            assert!(!is_redirect(status), "status {status} must not be followed");
        }
    }
}
