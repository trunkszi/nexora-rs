//! Request view, deferred responder, and the application service trait.

use std::{
    cell::{Cell, RefCell},
    net::SocketAddr,
    rc::Rc,
};

use crate::{
    Error, Result, StatusCode, SubsystemInbox, Version,
    inbox::DeferredResponse,
    proto::{Bytes, Request, Response},
};

/// Per-request view passed to [`HttpService::call`].
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub(super) peer: Option<SocketAddr>,
    pub(super) params: Vec<(String, String)>,
    pub(super) version: Version,
    pub(super) stream_id: Option<u32>,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            peer: None,
            params: Vec::new(),
            version: Version::Http11,
            stream_id: None,
        }
    }
}

impl RequestContext {
    /// Returns the accepted peer, when the listener captured one.
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

    /// Returns the newest value stored for `name`.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Inserts `value` for `name`, replacing a previous value with the same name.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_param(&mut self, name: &str, value: &str) {
        if let Some((_, existing)) = self.params.iter_mut().find(|(key, _)| key == name) {
            *existing = String::from(value);
            return;
        }
        self.params.push((String::from(name), String::from(value)));
    }

    /// Replaces the entire parameter list.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_params(&mut self, params: Vec<(String, String)>) {
        self.params = params;
    }

    /// Returns the protocol version of the request being handled.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Returns the HTTP/2 stream id, or `None` for HTTP/1.1.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn stream_id(&self) -> Option<u32> {
        self.stream_id
    }
}

enum Sink {
    Live {
        inbox: SubsystemInbox,
        connection_id: u64,
        stream_id: Option<u32>,
        gate: Rc<Cell<bool>>,
    },
    Test(Rc<RefCell<Option<Response>>>),
}

/// Sends one response for a request, immediately or from a later turn.
///
/// Dropping an open responder that never called [`Self::respond`] queues
/// `500 Internal Server Error`.
pub struct Responder {
    sink: Option<Sink>,
    open: bool,
}

impl Responder {
    pub(super) fn live(
        inbox: SubsystemInbox,
        connection_id: u64,
        stream_id: Option<u32>,
        gate: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            sink: Some(Sink::Live {
                inbox,
                connection_id,
                stream_id,
                gate,
            }),
            open: true,
        }
    }

    /// Builds a responder that stores one response in `sink`.
    ///
    /// `open == false` makes [`Self::is_closed`] true, [`Self::respond`] returns
    /// [`Error::ConnectionClosed`], and drop sends nothing.
    /// An occupied or currently borrowed slot is also considered closed;
    /// neither sending nor dropping overwrites an existing response.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn for_test(sink: Rc<RefCell<Option<Response>>>, open: bool) -> Self {
        let open = open && sink.try_borrow_mut().is_ok_and(|slot| slot.is_none());
        Self {
            sink: Some(Sink::Test(sink)),
            open,
        }
    }

    /// Reports whether the client can no longer receive this response.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        if !self.open {
            return true;
        }
        match &self.sink {
            Some(Sink::Live { gate, .. }) => !gate.get(),
            Some(Sink::Test(sink)) => sink.try_borrow_mut().map_or(true, |slot| slot.is_some()),
            _ => false,
        }
    }

    /// Queues `response` and consumes the responder.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionClosed`] when the client is already gone or
    /// the test response slot is occupied or borrowed.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn respond(mut self, response: Response) -> Result<()> {
        if self.is_closed() {
            self.sink.take();
            return Err(Error::ConnectionClosed);
        }
        match self.sink.take() {
            Some(Sink::Live {
                inbox,
                connection_id,
                stream_id,
                ..
            }) => {
                inbox.defer_response(DeferredResponse::new(connection_id, stream_id, response));
                Ok(())
            }
            Some(Sink::Test(sink)) => {
                let mut slot = sink.try_borrow_mut().map_err(|_| Error::ConnectionClosed)?;
                if slot.is_some() {
                    return Err(Error::ConnectionClosed);
                }
                *slot = Some(response);
                Ok(())
            }
            None => Err(Error::ConnectionClosed),
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if self.is_closed() {
            return;
        }
        let Some(sink) = self.sink.take() else {
            return;
        };
        let response = Response::text(
            StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from_static(b"Internal Server Error"),
        );
        match sink {
            Sink::Live {
                inbox,
                connection_id,
                stream_id,
                ..
            } => {
                inbox.defer_response(DeferredResponse::new(connection_id, stream_id, response));
            }
            Sink::Test(sink) => {
                if let Ok(mut slot) = sink.try_borrow_mut()
                    && slot.is_none()
                {
                    *slot = Some(response);
                }
            }
        }
    }
}

/// Application entry for one HTTP request.
pub trait HttpService {
    /// Handles `req` by calling [`Responder::respond`] now or retaining `responder`.
    ///
    /// # Errors
    /// Returns an application error. The server still drains a dropped responder.
    ///
    /// # Panics
    /// Implementations should not panic; a panic aborts the current drive turn.
    fn call(&mut self, ctx: &mut RequestContext, req: Request, responder: Responder) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, StatusCode, Version, proto::Response};

    #[test]
    fn dropped_open_responder_sends_internal_error() {
        let sink = Rc::new(RefCell::new(None));
        drop(Responder::for_test(Rc::clone(&sink), true));
        let response = match sink.borrow_mut().take() {
            Some(response) => response,
            None => panic!("missing fallback response"),
        };
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.body.as_ref(), b"Internal Server Error");
    }

    #[test]
    fn closed_responder_rejects_without_fallback() {
        let sink = Rc::new(RefCell::new(None));
        let responder = Responder::for_test(Rc::clone(&sink), false);
        assert!(responder.is_closed());
        let error = match responder.respond(Response::ok("late")) {
            Ok(()) => panic!("closed responder accepted a response"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::ConnectionClosed));
        assert!(sink.borrow().is_none());
    }

    #[test]
    fn occupied_response_slot_rejects_sends_and_drop_without_overwriting() -> Result<()> {
        let sink = Rc::new(RefCell::new(None));
        let pending = Responder::for_test(Rc::clone(&sink), true);
        Responder::for_test(Rc::clone(&sink), true).respond(Response::ok("first"))?;
        assert!(pending.is_closed());
        assert!(matches!(
            pending.respond(Response::ok("second")),
            Err(Error::ConnectionClosed)
        ));
        drop(Responder::for_test(Rc::clone(&sink), true));
        let closed = Responder::for_test(Rc::clone(&sink), true);
        let first = sink.borrow_mut().take();
        assert_eq!(
            first.as_ref().map(|response| response.body.as_ref()),
            Some(&b"first"[..])
        );
        assert!(closed.is_closed());
        assert!(matches!(
            closed.respond(Response::ok("reopened")),
            Err(Error::ConnectionClosed)
        ));
        assert!(sink.borrow().is_none());
        Ok(())
    }

    #[test]
    fn borrowed_response_slot_fails_closed_without_panicking() {
        let sink = Rc::new(RefCell::new(None));
        let borrow = sink.borrow();
        let responder = Responder::for_test(Rc::clone(&sink), true);
        assert!(responder.is_closed());
        assert!(matches!(
            responder.respond(Response::ok("busy")),
            Err(Error::ConnectionClosed)
        ));
        drop(Responder::for_test(Rc::clone(&sink), true));
        assert!(borrow.is_none());
    }

    #[test]
    fn set_param_replaces_one_name_and_set_params_replaces_the_list() {
        let mut ctx = RequestContext::default();
        ctx.set_param("id", "7");
        ctx.set_param("id", "8");
        assert_eq!(ctx.param("id"), Some("8"));
        ctx.set_params(vec![(String::from("q"), String::from("1"))]);
        assert_eq!(ctx.param("id"), None);
        assert_eq!(ctx.param("q"), Some("1"));
        assert_eq!(ctx.version(), Version::Http11);
        assert_eq!(ctx.stream_id(), None);
        assert_eq!(ctx.peer_addr(), None);
    }
}
