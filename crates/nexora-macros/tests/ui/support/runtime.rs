//! Compile-only runtime signatures copied from the shared contract.
//!
//! These definitions verify generated trait implementations. They do not
//! represent network dispatch, responder lifecycle, or server behavior.

use nexora_proto::{Request, Response, WebSocketCloseFrame, WebSocketMessage};

#[derive(Debug)]
pub struct Error;

pub type Result<T> = std::result::Result<T, Error>;

pub struct RequestContext;

pub struct Responder;

impl Responder {
    /// Accept a response at the compile-only signature seam.
    ///
    /// # Errors
    /// This signature fixture always succeeds.
    pub fn respond(self, _response: Response) -> Result<()> {
        Ok(())
    }
}

pub trait HttpService {
    /// Dispatch an incoming request.
    ///
    /// # Errors
    /// Implementations may return a handler error.
    fn call(
        &mut self,
        ctx: &mut RequestContext,
        request: Request,
        responder: Responder,
    ) -> Result<()>;
}

pub struct WebSocketServerSession;

pub trait WebSocketUpgradeHandler {
    /// Handle an opened session.
    ///
    /// # Errors
    /// Implementations may return a handler error.
    fn on_open(&mut self, _session: &mut WebSocketServerSession) -> Result<()> {
        Ok(())
    }

    /// Handle an incoming message.
    ///
    /// # Errors
    /// Implementations may return a handler error.
    fn on_message(&mut self, session: &mut WebSocketServerSession, message: WebSocketMessage) -> Result<()>;

    /// Handle a closed session.
    ///
    /// # Errors
    /// Implementations may return a handler error.
    fn on_close(
        &mut self,
        _session: &mut WebSocketServerSession,
        _close: Option<WebSocketCloseFrame>,
    ) -> Result<()> {
        Ok(())
    }

    /// Observe a session error.
    fn on_error(&mut self, _session: &mut WebSocketServerSession, _error: &Error) {}
}
