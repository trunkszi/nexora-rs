//! Re-entrant command staging shared by the client and server drive loops.
//!
//! [`ClientContext`] is the handle passed to every terminal request callback and
//! every timer expiry. Inside such a callback user code may submit a follow-up
//! request, cancel an in-flight one, arm a timer, or address a WebSocket
//! session. They only stage an [`InboxCommand`] and never touch the proactor,
//! sockets, or connections.
//!
//! One queue is shared by every [`SubsystemInbox`] and [`ClientContext`] handle
//! derived from it. It also receives DNS outcomes from resolver callbacks,
//! deferred server replies from the server `Responder` (including its `500`
//! fallback), and external WebSocket commands. Drive loops pop commands between
//! reactor turns and apply them in staging order; each loop must handle the
//! variants its subsystem owns.
//!
//! The queue lives in an `UnsafeCell` rather than a `RefCell`: a callback that
//! stages a follow-up command while a borrow is live would panic inside
//! `RefCell`. Every access is a short borrow inside a function that runs no user
//! code, and [`SubsystemInbox::pop`] moves a command out before the drive loop
//! runs its callback. Handles are `!Send + !Sync` (`Rc` plus `PhantomData`), so
//! accesses stay on one thread, and that thread must keep the global allocator
//! from re-entering this queue (a push can allocate).

use std::{marker::PhantomData, net::SocketAddr, rc::Rc, time::Duration};

use uarch::prelude::*;

use crate::{
    error::{Error, Result},
    proto::{Request, Response, WebSocketCloseFrame, WebSocketMessage},
};

/// Monotonic identifier assigned to one submitted request.
///
/// Reservation starts at one and advances by one per call. Values handed out by
/// one inbox stay unique until its counter wraps after `2^64` reservations;
/// separate inboxes number their identifiers independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

impl RequestId {
    /// Creates an identifier from its raw value.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw identifier value.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Monotonic identifier assigned to one registered timer.
///
/// Reservation starts at one and advances by one per call. Values handed out by
/// one inbox stay unique until its counter wraps after `2^64` reservations;
/// separate inboxes number their identifiers independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(pub u64);

impl TimerId {
    /// Creates an identifier from its raw value.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw identifier value.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Monotonic identifier assigned to one WebSocket session.
///
/// Allocated values stay below `2^52`, the width WebSocket completion payloads
/// reserve for a session identifier, so masking a raw value round-trips it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebSocketSessionId(pub u64);

impl WebSocketSessionId {
    /// Creates an identifier from its raw value.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw identifier value.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Terminal callback registered with a request submission.
///
/// The drive loop invokes it exactly once with `Ok(Response)` or with the error
/// that ended the exchange, including cancellation and timeout.
pub type ResponseCallback =
    Box<dyn FnOnce(&mut ClientContext, RequestId, Result<Response>) + 'static>;

/// Expiry callback registered with a timer.
///
/// The drive loop invokes it exactly once, after the requested delay has
/// elapsed, unless the timer is discarded during shutdown.
pub type TimerCallback = Box<dyn FnOnce(&mut ClientContext, TimerId) + 'static>;

/// Address family a DNS query asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// IPv4 `A` records.
    Ipv4,
    /// IPv6 `AAAA` records.
    Ipv6,
}

/// Outcome of one host lookup, delivered through the inbox.
#[derive(Debug, Clone)]
pub struct DnsResolution {
    /// Host name that was queried, as written by the caller.
    pub host: String,
    /// Port the lookup was started for.
    pub port: u16,
    /// Address family that was queried.
    pub family: AddressFamily,
    /// Resolved addresses; empty when the lookup failed.
    pub addrs: Vec<SocketAddr>,
    /// Lifetime the resolver reported for the answer.
    pub ttl: Duration,
    /// Failure text, or `None` for a usable answer.
    pub error: Option<String>,
}

impl DnsResolution {
    /// Creates a lookup result from the address list the resolver returned.
    ///
    /// An empty list is kept as given, so [`Self::is_usable`] reports the
    /// answer as unusable without discarding the failure reason.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn success(
        host: impl Into<String>,
        port: u16,
        family: AddressFamily,
        addrs: Vec<SocketAddr>,
        ttl: Duration,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            family,
            addrs,
            ttl,
            error: None,
        }
    }

    /// Creates a failed lookup result with no addresses and a zero TTL.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn failure(
        host: impl Into<String>,
        port: u16,
        family: AddressFamily,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            family,
            addrs: Vec::new(),
            ttl: Duration::ZERO,
            error: Some(reason.into()),
        }
    }

    /// Reports whether the lookup produced at least one usable address.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn is_usable(&self) -> bool {
        self.error.is_none() && !self.addrs.is_empty()
    }
}

/// Server reply staged for a connection after a handler deferred it.
#[derive(Debug, Clone)]
pub struct DeferredResponse {
    /// Server-assigned opaque connection identity.
    pub connection_id: u64,
    /// HTTP/2 stream identifier, or `None` for an HTTP/1.1 exchange.
    pub stream_id: Option<u32>,
    /// Response to write on that connection or stream.
    pub response: Response,
}

impl DeferredResponse {
    /// Creates a reply bound to one connection and optional stream.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(connection_id: u64, stream_id: Option<u32>, response: Response) -> Self {
        Self {
            connection_id,
            stream_id,
            response,
        }
    }
}

/// Staged request submission.
pub struct SubmitCommand {
    /// Identifier reserved for this request.
    pub request_id: RequestId,
    /// Request to send once the drive loop reaches this command.
    pub request: Request,
    /// Terminal callback invoked with the outcome.
    pub callback: ResponseCallback,
}

/// Staged timer registration.
pub struct TimerCommand {
    /// Identifier reserved for this timer.
    pub timer_id: TimerId,
    /// Delay relative to the moment the drive loop applies the command.
    pub delay: Duration,
    /// Callback invoked when the delay elapses.
    pub callback: TimerCallback,
}

/// Command or event staged by a runtime callback for the drive loop.
pub enum InboxCommand {
    /// A request submission raised by user code or a re-entrant callback.
    Submit(SubmitCommand),
    /// Cancellation of an in-flight request.
    Cancel(RequestId),
    /// A timer registration.
    SetTimer(TimerCommand),
    /// A message to write on an existing WebSocket session.
    WebSocketSend {
        /// Session the message is addressed to.
        session_id: WebSocketSessionId,
        /// Message to encode and write.
        message: WebSocketMessage,
    },
    /// A close handshake on an existing WebSocket session.
    WebSocketClose {
        /// Session to close.
        session_id: WebSocketSessionId,
        /// Optional close status and reason to send.
        close: Option<WebSocketCloseFrame>,
    },
    /// A host lookup completed by the resolver.
    DnsResolved(DnsResolution),
    /// A server reply produced after a handler deferred it.
    Respond(DeferredResponse),
}

mod shared;
use shared::InboxShared;

/// Shared handle used to stage commands and receive runtime events.
///
/// DNS completion callbacks hold one clone, the server `Responder` holds one
/// clone, and external WebSocket control paths hold one clone. Cloning the
/// handle shares the same queue and identifier counters.
pub struct SubsystemInbox {
    shared: Rc<InboxShared>,
    not_send_or_sync: PhantomData<*mut ()>,
}

impl SubsystemInbox {
    /// Creates an empty inbox with all identifier counters at zero.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new() -> Self {
        Self {
            shared: Rc::new(InboxShared::new()),
            not_send_or_sync: PhantomData,
        }
    }

    /// Creates a context that stages into the same queue and counters.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn context(&self) -> ClientContext {
        ClientContext {
            shared: Rc::clone(&self.shared),
            not_send_or_sync: PhantomData,
        }
    }

    /// Stages a command for the drive loop.
    ///
    /// Commands staged after the last handle begins its final drain are
    /// discarded.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[inline]
    pub fn push(&self, command: InboxCommand) {
        self.shared.push(command);
    }

    /// Removes the oldest staged command.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[inline]
    pub fn pop(&self) -> Option<InboxCommand> {
        self.shared.pop()
    }

    /// Returns the number of staged commands.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[hot_inline]
    pub fn len(&self) -> usize {
        self.shared.len()
    }

    /// Reports whether no command is staged.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[hot_inline]
    pub fn is_empty(&self) -> bool {
        self.shared.is_empty()
    }

    /// Reserves the next request identifier.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn next_request_id(&self) -> RequestId {
        RequestId(InboxShared::advance(&self.shared.next_request_id))
    }

    /// Reserves the next timer identifier.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn next_timer_id(&self) -> TimerId {
        TimerId(InboxShared::advance(&self.shared.next_timer_id))
    }

    /// Reserves the next WebSocket session identifier below `2^52`.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn next_websocket_session_id(&self) -> WebSocketSessionId {
        const WS_ID_MASK: u64 = (1 << 52) - 1;
        WebSocketSessionId(
            InboxShared::advance(&self.shared.next_websocket_session_id) & WS_ID_MASK,
        )
    }

    /// Stages the outcome of a host lookup.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn dns_resolved(&self, resolution: DnsResolution) {
        self.push(InboxCommand::DnsResolved(resolution));
    }

    /// Stages a deferred server reply.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn defer_response(&self, response: DeferredResponse) {
        self.push(InboxCommand::Respond(response));
    }

    /// Stages a message for an existing WebSocket session.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn websocket_send(&self, session_id: WebSocketSessionId, message: WebSocketMessage) {
        self.push(InboxCommand::WebSocketSend {
            session_id,
            message,
        });
    }

    /// Stages a close handshake for an existing WebSocket session.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn websocket_close(
        &self,
        session_id: WebSocketSessionId,
        close: Option<WebSocketCloseFrame>,
    ) {
        self.push(InboxCommand::WebSocketClose { session_id, close });
    }
}

impl Clone for SubsystemInbox {
    /// Clones the handle, sharing the queue and identifier counters.
    fn clone(&self) -> Self {
        Self {
            shared: Rc::clone(&self.shared),
            not_send_or_sync: PhantomData,
        }
    }
}

impl Default for SubsystemInbox {
    /// Creates an empty inbox, equivalent to [`SubsystemInbox::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Re-entrant handle passed to terminal callbacks and timer expiries.
///
/// Every method stages work for the drive loop instead of applying it
/// immediately, so a callback can submit, cancel, arm timers, and issue
/// WebSocket commands while the loop is inside user code.
pub struct ClientContext {
    shared: Rc<InboxShared>,
    not_send_or_sync: PhantomData<*mut ()>,
}

impl ClientContext {
    /// Creates a context that stages into `inbox`'s queue and counters.
    ///
    /// This is equivalent to [`SubsystemInbox::context`] and is the constructor
    /// used by the client drive loop when it needs an owned context to pass to
    /// callbacks.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(inbox: &SubsystemInbox) -> Self {
        inbox.context()
    }

    /// Reserves a request identifier and stages the request.
    ///
    /// The callback is stored with the command and invoked exactly once by the
    /// drive loop with the terminal outcome of this request.
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] once the inbox has begun draining staged
    /// callbacks, because that submission could never be applied. Otherwise the
    /// result is reserved for admission control such as a bounded in-flight
    /// limit; no such limit is enforced yet.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn submit<F>(&mut self, req: Request, on_complete: F) -> Result<RequestId>
    where
        F: FnOnce(&mut ClientContext, RequestId, Result<Response>) + 'static,
    {
        if self.shared.is_closed() {
            return Err(closed_inbox());
        }
        let request_id = RequestId(InboxShared::advance(&self.shared.next_request_id));
        let callback: ResponseCallback = Box::new(on_complete);
        self.stage(InboxCommand::Submit(SubmitCommand {
            request_id,
            request: req,
            callback,
        }));
        Ok(request_id)
    }

    /// Stages cancellation of an in-flight request.
    ///
    /// The request's terminal callback still runs exactly once; it receives the
    /// cancellation error rather than a response.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn cancel(&mut self, request_id: RequestId) {
        self.stage(InboxCommand::Cancel(request_id));
    }

    /// Reserves a timer identifier and stages the timer.
    ///
    /// The delay is measured from the moment the drive loop applies the
    /// command, not from this call.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_timer<F>(&mut self, delay: Duration, on_expire: F) -> TimerId
    where
        F: FnOnce(&mut ClientContext, TimerId) + 'static,
    {
        let timer_id = TimerId(InboxShared::advance(&self.shared.next_timer_id));
        let callback: TimerCallback = Box::new(on_expire);
        self.stage(InboxCommand::SetTimer(TimerCommand {
            timer_id,
            delay,
            callback,
        }));
        timer_id
    }

    /// Stages a message for an existing WebSocket session.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn websocket_send(&mut self, session_id: WebSocketSessionId, msg: WebSocketMessage) {
        self.stage(InboxCommand::WebSocketSend {
            session_id,
            message: msg,
        });
    }

    /// Stages a close handshake for an existing WebSocket session.
    ///
    /// # Errors
    /// This operation does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn websocket_close(
        &mut self,
        session_id: WebSocketSessionId,
        close: Option<WebSocketCloseFrame>,
    ) {
        self.stage(InboxCommand::WebSocketClose { session_id, close });
    }

    /// Stages a command without running user code.
    #[inline]
    fn stage(&self, command: InboxCommand) {
        self.shared.push(command);
    }
}

impl Drop for SubsystemInbox {
    fn drop(&mut self) {
        drain_if_last(&self.shared);
    }
}

impl Drop for ClientContext {
    fn drop(&mut self) {
        drain_if_last(&self.shared);
    }
}

/// Delivers `Cancelled` to staged terminal callbacks when the last handle drops.
///
/// The context created here keeps the strong count above one while the drain
/// runs, so its own drop cannot re-enter this function.
#[cold_sink]
fn drain_if_last(shared: &Rc<InboxShared>) {
    if Rc::strong_count(shared) != 1 {
        return;
    }
    shared.begin_drain();
    let mut context = ClientContext {
        shared: Rc::clone(shared),
        not_send_or_sync: PhantomData,
    };
    while let Some(command) = shared.pop() {
        if let InboxCommand::Submit(submit) = command {
            (submit.callback)(&mut context, submit.request_id, Err(Error::Cancelled));
        }
    }
}

#[cold_sink]
fn closed_inbox() -> Error {
    Error::InvalidState("inbox is closed".to_owned())
}
