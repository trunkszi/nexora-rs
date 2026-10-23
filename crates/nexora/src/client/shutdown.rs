//! Explicit retirement of the client's socket and timer operations.

use std::time::{Duration, Instant};

use liburing::{CompletionDispatcher, Proactor, UringError};

use super::HttpClient;
use crate::{
    Error, Result,
    inbox::InboxCommand,
    pool::{operation_id, stage_cancel},
};

impl HttpClient {
    /// Cancels requests and drives every connection and timer to final completion.
    ///
    /// Call this on the owning thread before dropping the client, while its
    /// proactor remains usable. The call drives the shared ring without sleeping
    /// and leaves sibling subsystems active. Repeated calls are harmless; new
    /// requests are rejected once shutdown begins. User timers do not fire.
    ///
    /// # Errors
    /// This method does not return errors.
    ///
    /// # Panics
    /// Panics if the proactor cannot submit or dispatch teardown operations.
    /// Pending buffers remain retained on failure. User request callbacks may panic.
    pub fn shutdown(&mut self, proactor: &mut Proactor) {
        if let Err(error) = self.shutdown_with(proactor, &mut crate::dispatch::RejectForeign) {
            panic!("HTTP client shutdown failed: {error}");
        }
    }

    /// Retires client and DNS I/O while routing peer completions on the same ring.
    ///
    /// The ring remains open. On failure the caller retains both ring and driver
    /// and can retry; pending buffers must remain alive until final completion.
    /// # Errors
    /// Returns dispatch/submission failures or expiry of the five-second budget.
    /// # Panics
    /// User callbacks may panic.
    pub fn shutdown_with<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        proactor: &mut Proactor,
        peer: &mut D,
    ) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        self.shutting_down = true;
        self.resolver.begin_shutdown(proactor)?;
        let requests: Vec<_> = self.requests.keys().copied().collect();
        for id in requests {
            let _cancelled = self.abort(proactor, id, Error::Cancelled);
        }
        self.intents.clear();
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Uring(UringError::Wait(libc::ETIMEDOUT)));
            }
            match self.drive_with(proactor, peer) {
                Ok(_) => {}
                Err(Error::Uring(UringError::SqRingFull)) => {
                    proactor.submit()?;
                    continue;
                }
                Err(error) => return Err(error),
            }
            if self.conns.is_empty()
                && self.timers.is_empty()
                && self.inbox.is_empty()
                && !self.resolver.has_pending_io()
            {
                return Ok(());
            }
        }
    }

    pub(super) fn flush_shutdown(&mut self, proactor: &mut Proactor) -> Result<()> {
        while let Some(command) = self.inbox.pop() {
            if let InboxCommand::Submit(command) = command {
                self.deliver(
                    command.request_id,
                    Some(command.callback),
                    Error::ConnectionClosed,
                );
            }
        }
        self.intents.clear();
        let ids: Vec<_> = self.conns.keys().copied().collect();
        for id in ids {
            self.start_close(proactor, id)?;
        }
        for &token in self.timers.keys() {
            if !self.cancelling.contains(&token) {
                let target = operation_id(self.config.net_subsystem, token)?;
                stage_cancel(proactor, self.config.net_subsystem, target)?;
                let _inserted = self.cancelling.insert(token);
            }
        }
        self.resolver.flush(proactor)
    }

    fn start_close(&mut self, proactor: &mut Proactor, id: u64) -> Result<()> {
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.want_close = true;
            if conn.close_op.is_none() {
                // SAFETY: The connection owns this descriptor until its close
                // completion. Shutdown wakes socket operations without recycling
                // the descriptor or releasing any kernel-referenced allocation.
                unsafe { libc::shutdown(conn.fd, libc::SHUT_RDWR) };
            }
        }
        self.flush_connection(proactor, id)
    }
}

impl Drop for HttpClient {
    fn drop(&mut self) {
        // An armed timeout retains a pointer into its operand until the final CQE.
        // Explicit shutdown drains it; Drop alone cannot observe that completion.
        for (_, entry) in self.timers.drain() {
            std::mem::forget(entry._timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io::{Read, Write},
        net::TcpListener,
        rc::Rc,
        time::{Duration, Instant},
    };

    use liburing::{Proactor, ProactorConfig};
    use nexora_proto::Request;

    use crate::{ClientConfig, Error, HttpClient, Result};

    fn exchange_then_shutdown(respond: bool) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let peer = std::thread::spawn(move || -> std::io::Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            let mut request = Vec::new();
            let mut byte = [0u8];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte)?;
                request.push(byte[0]);
            }
            if respond {
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
            }
            assert_eq!(socket.read(&mut byte)?, 0, "client must send EOF");
            Ok(())
        });
        let mut ring = Proactor::new(ProactorConfig::default())?;
        let mut client = HttpClient::new(&mut ring, ClientConfig::default())?;
        let calls = Rc::new(Cell::new(0));
        let observed = Rc::clone(&calls);
        let request = Request::get(&format!("http://{address}/"))?;
        client.submit(&mut ring, request, move |_, _, result| {
            if respond {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(Error::Cancelled)));
            }
            observed.set(observed.get() + 1);
        })?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            client.drive(&mut ring)?;
            let ready = if respond {
                calls.get() == 1
            } else {
                client.conns.values().any(|conn| {
                    conn.rx_op.is_some()
                        && conn.send_op.is_none()
                        && conn.tx_pending.is_empty()
                        && conn.tx_inflight.is_empty()
                })
            };
            if ready {
                break;
            }
            assert!(Instant::now() < deadline, "request did not reach the peer");
        }
        let descriptors: Vec<_> = client.conns.values().map(|conn| conn.fd).collect();
        assert!(!descriptors.is_empty());
        assert!(client.conns.values().any(|conn| conn.rx_op.is_some()));
        let timer_fired = Rc::new(Cell::new(false));
        let fired = Rc::clone(&timer_fired);
        client.set_timer(&mut ring, Duration::from_secs(60), move |_, _| {
            fired.set(true)
        })?;
        client.shutdown(&mut ring);
        assert!(client.conns.is_empty());
        assert!(client.timers.is_empty());
        assert!(client.ops.is_empty());
        assert_eq!(client.active_request_count(), 0);
        assert_eq!(calls.get(), 1, "terminal callback must fire exactly once");
        assert!(!timer_fired.get());
        for fd in descriptors {
            // SAFETY: F_GETFD only queries the saved descriptor number.
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        }
        client.shutdown(&mut ring);
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            client.submit(
                &mut ring,
                Request::get(&format!("http://{address}/"))?,
                |_, _, _| {
                    panic!("rejected submission must not run its callback");
                }
            ),
            Err(Error::ConnectionClosed)
        ));
        peer.join()
            .map_err(|_| Error::InvalidState("peer thread panicked".into()))??;
        ring.shutdown()?;
        Ok(())
    }

    #[test]
    fn lifecycle_shutdown_retires_a_keepalive_receive_and_closes_its_descriptor() -> Result<()> {
        exchange_then_shutdown(true)
    }

    #[test]
    fn lifecycle_shutdown_cancels_an_active_request_and_drains_timers() -> Result<()> {
        exchange_then_shutdown(false)
    }
}
