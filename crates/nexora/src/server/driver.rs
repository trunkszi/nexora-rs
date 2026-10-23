//! Caller-owned completion dispatch and the public server handle.

use std::{cell::UnsafeCell, net::SocketAddr, rc::Rc};

use liburing::{Completion, CompletionDispatcher, Proactor, SubmissionContext};

use super::{
    config::{ServerBuilder, ServerConfig},
    model::State,
    net::listen,
    service::HttpService,
};
use crate::{
    Error, Result, SocketState, WebSocketMessage, WebSocketSessionId,
    websocket_server::WebSocketUpgradeHandler,
};

/// HTTP server bound to one proactor subsystem and one listening socket.
pub struct HttpServer<S> {
    state: Rc<UnsafeCell<State<S>>>,
}

impl<S: HttpService> HttpServer<S> {
    /// Creates a builder for `service`.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn builder(service: S) -> ServerBuilder<S> {
        ServerBuilder::new(service)
    }
}

impl<S: HttpService> HttpServer<S> {
    /// Listens on `addr` and arms accept under `config.net_subsystem`.
    ///
    /// # Errors
    /// Returns a socket, bind, listen, buffer, or submission error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn bind(
        proactor: &mut Proactor,
        addr: SocketAddr,
        config: ServerConfig,
        service: S,
    ) -> Result<Self> {
        if config.io_buffer_size == 0 {
            return Err(Error::InvalidState(String::from(
                "io buffer size must be non-zero",
            )));
        }
        let (fd, local) = listen(addr, config.backlog.max(1))?;
        let mut server = Self {
            state: Rc::new(UnsafeCell::new(State::new(config, service, fd, local))),
        };
        let state = server.state_mut();
        state.arm(proactor)?;
        proactor.submit()?;
        Ok(server)
    }

    /// Installs the WebSocket upgrade handler for an exact request path.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn with_websocket_handler<W>(mut self, path: impl Into<String>, handler: W) -> Self
    where
        W: WebSocketUpgradeHandler + 'static,
    {
        let state = self.state_mut();
        state.websocket_path = path.into();
        state.websocket = Some(Box::new(handler));
        self
    }

    /// Returns the address actually bound, including an ephemeral port.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.state().local
    }

    /// Applies completions already delivered to this subsystem, then submits I/O.
    ///
    /// The caller routes CQEs through this server's completion dispatcher.
    /// This method applies its inbox and stages I/O without harvesting the ring.
    ///
    /// # Errors
    /// Returns a protocol, socket-state, or submission error.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn drive(&mut self, proactor: &mut Proactor) -> Result<usize> {
        let state = self.state_mut();
        let applied = state.apply_completions();
        let drained = state.drain_inbox();
        let pumped = state.pump_all();
        state.arm(proactor)?;
        proactor.submit()?;
        let count = applied?;
        drained?;
        pumped?;
        Ok(count)
    }

    /// Encodes `message` for an accepted WebSocket session.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionClosed`] when `session_id` is unknown, or a
    /// codec error when the session can no longer send.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn websocket_send(
        &mut self,
        session_id: WebSocketSessionId,
        message: WebSocketMessage,
    ) -> Result<()> {
        self.state_mut().enqueue_websocket(session_id, message)
    }

    /// Queues a WebSocket close and finishes the connection after it is written.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionClosed`] when `session_id` is unknown, or a
    /// codec error when the close frame cannot be encoded.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn websocket_close(
        &mut self,
        session_id: WebSocketSessionId,
        close: Option<crate::WebSocketCloseFrame>,
    ) -> Result<()> {
        self.state_mut()
            .enqueue_websocket(session_id, WebSocketMessage::Close(close))
    }

    /// Stops accept, sends HTTP/2 `GOAWAY`, and marks HTTP/1 responses `Connection: close`.
    ///
    /// # Errors
    /// Returns a protocol or submission error while queueing `GOAWAY`.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn initiate_graceful_shutdown(&mut self, proactor: &mut Proactor) -> Result<()> {
        let state = self.state_mut();
        state.shutting_down = true;
        let slots: Vec<usize> = (0..state.conns.len()).collect();
        for slot in slots {
            state.graceful(slot)?;
        }
        state.arm(proactor)?;
        proactor.submit()?;
        Ok(())
    }

    /// Counts accepted sockets that have not finished close.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.state()
            .conns
            .iter()
            .filter(|slot| {
                slot.as_ref()
                    .is_some_and(|conn| conn.sock.state() != SocketState::Closed)
            })
            .count()
    }

    fn state(&self) -> &State<S> {
        // SAFETY: the server is `!Send` through `Rc` and runs on the ring thread.
        // Dispatch and progress require an exclusive server borrow; no state
        // reference is retained across a completion callback.
        unsafe { &*self.state.get() }
    }

    fn state_mut(&mut self) -> &mut State<S> {
        // SAFETY: same exclusive ring-thread ownership as `state`. The mutable
        // borrow ends before any poll, so later dispatch cannot alias it.
        unsafe { &mut *self.state.get() }
    }
}

impl<S> Drop for HttpServer<S> {
    fn drop(&mut self) {
        // SAFETY: see `state`. This read only decides whether in-flight SQEs
        // still point at the allocation.
        let busy = unsafe { &*self.state.get() }.busy();
        if busy {
            // Keep the allocation alive until the kernel finishes SQEs that
            // reference its buffers and the accept address.
            std::mem::forget(Rc::clone(&self.state));
        }
    }
}

impl<S: HttpService> CompletionDispatcher for HttpServer<S> {
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        if completion.operation_id.subsystem_id() != self.state().config.net_subsystem {
            return Err(liburing::UringError::InvalidSubsystemId(
                completion.operation_id.subsystem_id().raw(),
            ));
        }
        submissions.claim_completion(completion)?;
        self.state_mut().completions.push(completion);
        Ok(())
    }
}

impl<S: HttpService> crate::dispatch::CompletionRoute for HttpServer<S> {
    fn accepts(&self, subsystem: liburing::SubsystemId) -> bool {
        subsystem == self.state().config.net_subsystem
    }
}
