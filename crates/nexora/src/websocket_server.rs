//! Server-side WebSocket session handles.
//!
//! [`WebSocketServerSession`] queues outbound frames for the HTTP server to encode
//! after the callback returns. [`WebSocketUpgradeHandler`] is the registration
//! surface installed with [`crate::HttpServer::with_websocket_handler`].

use std::net::SocketAddr;

use crate::{
    Error, Result, WebSocketCloseFrame, WebSocketMessage, WebSocketSessionId, proto::Bytes,
};

/// One accepted WebSocket connection as seen by an upgrade handler.
///
/// Sends queue [`WebSocketMessage`] values. The server encodes them with its
/// WebSocket codec when the callback returns, and when [`crate::HttpServer::websocket_send`]
/// is used from outside the callback.
pub struct WebSocketServerSession {
    id: WebSocketSessionId,
    peer: Option<SocketAddr>,
    outbound: Vec<WebSocketMessage>,
    closed: bool,
}

impl WebSocketServerSession {
    /// Builds a session that records frames without a socket.
    ///
    /// `peer` is reported by [`Self::peer_addr`]. No upgrade or I/O is performed.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn for_test(id: WebSocketSessionId, peer: Option<SocketAddr>) -> Self {
        Self {
            id,
            peer,
            outbound: Vec::new(),
            closed: false,
        }
    }

    /// Returns the id used by [`crate::HttpServer::websocket_send`] and
    /// [`crate::HttpServer::websocket_close`].
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn id(&self) -> WebSocketSessionId {
        self.id
    }

    /// Returns the accepted peer address, when the listener captured one.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Queues one WebSocket message.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionClosed`] after [`Self::close`] or a received close.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn send(&mut self, message: WebSocketMessage) -> Result<()> {
        if self.closed {
            return Err(Error::ConnectionClosed);
        }
        if matches!(message, WebSocketMessage::Close(_)) {
            self.closed = true;
        }
        self.outbound.push(message);
        Ok(())
    }

    /// Queues one text message.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionClosed`] when the session has started closing.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn send_text(&mut self, text: impl Into<String>) -> Result<()> {
        self.send(WebSocketMessage::Text(text.into()))
    }

    /// Queues one binary message.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionClosed`] when the session has started closing.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn send_binary(&mut self, data: impl Into<Bytes>) -> Result<()> {
        self.send(WebSocketMessage::Binary(data.into()))
    }

    /// Queues a close frame and rejects later sends.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionClosed`] when a close was already queued.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn close(&mut self, close: Option<WebSocketCloseFrame>) -> Result<()> {
        self.send(WebSocketMessage::Close(close))
    }

    /// Reports whether a close frame is already queued.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn has_close(&self) -> bool {
        self.outbound
            .iter()
            .any(|message| matches!(message, WebSocketMessage::Close(_)))
    }

    /// Removes and returns every queued message, in queue order.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn take_outbound(&mut self) -> Vec<WebSocketMessage> {
        std::mem::take(&mut self.outbound)
    }
}

/// Callbacks for one server WebSocket endpoint.
///
/// Register an implementation with [`crate::HttpServer::with_websocket_handler`].
/// The HTTP service macro does not construct upgrade handlers.
pub trait WebSocketUpgradeHandler {
    /// Runs after the `101 Switching Protocols` response is queued.
    ///
    /// # Errors
    /// The default returns `Ok(())`. Overrides may return a driver error.
    ///
    /// # Panics
    /// The default does not panic.
    fn on_open(&mut self, session: &mut WebSocketServerSession) -> Result<()> {
        let _ = session;
        Ok(())
    }

    /// Runs for each data or control message after automatic `Pong` queueing.
    ///
    /// # Errors
    /// Returns a driver error. The server then calls [`Self::on_error`].
    ///
    /// # Panics
    /// Implementations should not panic; a panic aborts the drive turn.
    fn on_message(
        &mut self,
        session: &mut WebSocketServerSession,
        message: WebSocketMessage,
    ) -> Result<()>;

    /// Runs when a close frame arrives, before the echo close is forced.
    ///
    /// # Errors
    /// The default returns `Ok(())`.
    ///
    /// # Panics
    /// The default does not panic.
    fn on_close(
        &mut self,
        session: &mut WebSocketServerSession,
        close: Option<WebSocketCloseFrame>,
    ) -> Result<()> {
        let _ = (session, close);
        Ok(())
    }

    /// Runs when [`Self::on_open`], [`Self::on_message`], or [`Self::on_close`] fails.
    ///
    /// # Errors
    /// This callback does not return errors.
    ///
    /// # Panics
    /// The default does not panic.
    fn on_error(&mut self, session: &mut WebSocketServerSession, error: &Error) {
        let _ = (session, error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_test_session_queues_text_without_a_socket() {
        let mut session = WebSocketServerSession::for_test(WebSocketSessionId::new(4), None);
        session
            .send_text("ping")
            .unwrap_or_else(|error| panic!("send failed: {error}"));
        let queued = session.take_outbound();
        assert_eq!(queued.len(), 1);
        assert!(matches!(queued.first(), Some(WebSocketMessage::Text(text)) if text == "ping"));
        assert!(session.take_outbound().is_empty());
    }
}
