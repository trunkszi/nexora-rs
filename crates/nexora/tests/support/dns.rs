//! Loopback UDP and TCP DNS responder.
//!
//! Sockets and scheduled replies advance on the calling test thread through
//! `poll_all`; delayed replies never block the proactor.

use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{self, ErrorKind, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

/// One scripted DNS reply. Later queries repeat the last step.
#[derive(Clone, Debug)]
pub struct DnsStep {
    /// What this query produces.
    pub action: DnsAction,
    /// Minimum interval before the reply becomes eligible for sending.
    pub delay: Duration,
}

/// Reply selected for one DNS query.
#[derive(Clone, Debug)]
pub enum DnsAction {
    /// Consume the query and write nothing.
    Drop,
    /// UDP sets `TC` and omits answers. TCP returns the records.
    Truncate {
        /// IPv4 answers used on the TCP fallback.
        v4: Vec<Ipv4Addr>,
        /// IPv6 answers used on the TCP fallback.
        v6: Vec<Ipv6Addr>,
    },
    /// Return every address that matches the question type.
    Answer {
        /// A records.
        v4: Vec<Ipv4Addr>,
        /// AAAA records.
        v6: Vec<Ipv6Addr>,
    },
    /// Return one A record, advancing through `v4`.
    Rotate {
        /// Addresses yielded one per A query.
        v4: Vec<Ipv4Addr>,
    },
    /// Name error with the question echoed.
    NxDomain,
    /// UDP `A` is truncated, TCP `A` returns `v4`, and UDP `AAAA` is discarded.
    Family {
        /// IPv4 addresses returned by the TCP retry.
        v4: Vec<Ipv4Addr>,
    },
}

/// Ordered reply script for [`MockDns`].
#[derive(Clone, Debug)]
pub struct DnsPlan {
    steps: VecDeque<DnsStep>,
    rotate_at: usize,
    ttl: u32,
}

impl DnsPlan {
    /// Answers every A query with `v4`.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn answer(v4: Vec<Ipv4Addr>) -> Self {
        Self::from_step(DnsStep {
            action: DnsAction::Answer { v4, v6: Vec::new() },
            delay: Duration::ZERO,
        })
    }

    /// Answers with both address families.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn dual(v4: Vec<Ipv4Addr>, v6: Vec<Ipv6Addr>) -> Self {
        Self::from_step(DnsStep {
            action: DnsAction::Answer { v4, v6 },
            delay: Duration::ZERO,
        })
    }

    /// Name-error script.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn nxdomain() -> Self {
        Self::from_step(DnsStep {
            action: DnsAction::NxDomain,
            delay: Duration::ZERO,
        })
    }

    /// Starts a script with one action. Later [`Self::then`] steps follow it.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn script(action: DnsAction) -> Self {
        Self::from_step(DnsStep {
            action,
            delay: Duration::ZERO,
        })
    }

    /// Appends a step after the ones already queued.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn then(mut self, action: DnsAction) -> Self {
        self.steps.push_back(DnsStep {
            action,
            delay: Duration::ZERO,
        });
        self
    }

    /// Schedules the last step's reply after a nonblocking delay.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn delay(mut self, delay: Duration) -> Self {
        if let Some(step) = self.steps.back_mut() {
            step.delay = delay;
        }
        self
    }

    fn from_step(step: DnsStep) -> Self {
        let mut steps = VecDeque::new();
        steps.push_back(step);
        Self {
            steps,
            rotate_at: 0,
            ttl: 30,
        }
    }
}

thread_local! {
    static RESPONDERS: RefCell<Vec<Weak<RefCell<DnsState>>>> = const { RefCell::new(Vec::new()) };
}

const POLL_BATCH: usize = 64;

struct DnsState {
    udp: UdpSocket,
    tcp: TcpListener,
    plan: DnsPlan,
    udp_queries: usize,
    tcp_queries: usize,
    dropped: usize,
    peers: Vec<TcpPeer>,
    next_peer: usize,
    pending: VecDeque<(Instant, PendingReply)>,
}

enum PendingReply {
    Udp { peer: SocketAddr, bytes: Vec<u8> },
    Tcp { peer: usize, bytes: Vec<u8> },
}

struct TcpPeer {
    id: usize,
    stream: TcpStream,
    input: Vec<u8>,
    output: VecDeque<Vec<u8>>,
    written: usize,
    read_closed: bool,
}

/// Local UDP and TCP DNS responder advanced by the calling thread.
pub struct MockDns {
    udp_port: u16,
    tcp_port: u16,
    state: Rc<RefCell<DnsState>>,
}

impl MockDns {
    /// Binds nonblocking loopback sockets and registers them on this thread.
    ///
    /// # Errors
    /// Returns an I/O error if binding or configuring either socket fails.
    ///
    /// # Panics
    /// Does not panic.
    pub fn spawn(plan: DnsPlan) -> io::Result<Self> {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let udp_port = udp.local_addr()?.port();
        let tcp_port = tcp.local_addr()?.port();
        let state = Rc::new(RefCell::new(DnsState {
            udp,
            tcp,
            plan,
            udp_queries: 0,
            tcp_queries: 0,
            dropped: 0,
            peers: Vec::new(),
            next_peer: 0,
            pending: VecDeque::new(),
        }));
        RESPONDERS.with(|responders| responders.borrow_mut().push(Rc::downgrade(&state)));
        Ok(Self {
            udp_port,
            tcp_port,
            state,
        })
    }

    /// Replaces the reply script. Already scheduled replies keep their deadlines.
    /// The rotation cursor restarts at zero.
    ///
    /// # Panics
    /// Does not panic.
    pub fn set_plan(&self, plan: DnsPlan) {
        self.state.borrow_mut().plan = plan;
    }

    /// c-ares server list pointing UDP and TCP at this responder.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn servers_csv(&self) -> String {
        format!(
            "dns://127.0.0.1:{}?tcpport={}",
            self.udp_port, self.tcp_port
        )
    }

    /// UDP queries observed, including dropped ones.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn udp_queries(&self) -> usize {
        self.state.borrow().udp_queries
    }

    /// TCP DNS messages observed.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn tcp_queries(&self) -> usize {
        self.state.borrow().tcp_queries
    }

    /// UDP queries discarded by the script.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn dropped(&self) -> usize {
        self.state.borrow().dropped
    }
}

/// Advances live DNS responders on the current thread, pruning dropped ones.
///
/// # Errors
/// Returns unexpected socket I/O errors or unrepresentable reply deadlines.
///
/// # Panics
/// Does not panic.
pub(super) fn poll_all() -> io::Result<()> {
    RESPONDERS.with(|responders| {
        let mut responders = responders.borrow_mut();
        responders.retain(|state| state.strong_count() != 0);
        for state in responders.iter().filter_map(Weak::upgrade) {
            state.borrow_mut().poll(Instant::now())?;
        }
        Ok(())
    })
}

impl DnsState {
    fn poll(&mut self, now: Instant) -> io::Result<()> {
        let mut buffer = [0u8; 2048];
        for _ in 0..POLL_BATCH {
            match self.udp.recv_from(&mut buffer) {
                Ok((size, peer)) => {
                    self.udp_queries = self.udp_queries.saturating_add(1);
                    if let Some((delay, bytes)) = reply(&buffer[..size], false, self) {
                        self.schedule(now, delay, PendingReply::Udp { peer, bytes })?;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        for _ in 0..POLL_BATCH {
            match self.tcp.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    let id = self.next_peer;
                    self.next_peer = id
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("DNS peer ID overflow"))?;
                    self.peers.push(TcpPeer {
                        id,
                        stream,
                        input: Vec::new(),
                        output: VecDeque::new(),
                        written: 0,
                        read_closed: false,
                    });
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let mut peers = std::mem::take(&mut self.peers);
        for peer in &mut peers {
            match peer.read_queries() {
                Ok(queries) => {
                    for query in queries {
                        self.tcp_queries = self.tcp_queries.saturating_add(1);
                        if let Some((delay, bytes)) = reply(&query, true, self) {
                            let length = u16::try_from(bytes.len()).map_err(|_| {
                                io::Error::other("DNS reply exceeds TCP length field")
                            })?;
                            let mut frame = Vec::with_capacity(bytes.len() + 2);
                            frame.extend_from_slice(&length.to_be_bytes());
                            frame.extend_from_slice(&bytes);
                            self.schedule(
                                now,
                                delay,
                                PendingReply::Tcp {
                                    peer: peer.id,
                                    bytes: frame,
                                },
                            )?;
                        }
                    }
                }
                Err(error) if peer_error(&error) => peer.read_closed = true,
                Err(error) => return Err(error),
            }
        }
        self.peers = peers;
        // Deadlines need not be ordered: a later query can have a shorter delay.
        for _ in 0..self.pending.len() {
            let Some((deadline, reply)) = self.pending.pop_front() else {
                break;
            };
            if deadline > now {
                self.pending.push_back((deadline, reply));
                continue;
            }
            match reply {
                PendingReply::Udp { peer, bytes } => match self.udp.send_to(&bytes, peer) {
                    Ok(size) if size == bytes.len() => {}
                    Ok(_) => {
                        return Err(io::Error::new(ErrorKind::WriteZero, "partial DNS datagram"));
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) =>
                    {
                        self.pending
                            .push_back((deadline, PendingReply::Udp { peer, bytes }));
                    }
                    Err(error) => return Err(error),
                },
                PendingReply::Tcp { peer, bytes } => {
                    if let Some(peer) = self.peers.iter_mut().find(|candidate| candidate.id == peer)
                    {
                        peer.output.push_back(bytes);
                    }
                }
            }
        }
        let mut error = None;
        self.peers.retain_mut(|peer| {
            if let Err(failure) = peer.flush() {
                if !peer_error(&failure) {
                    error = Some(failure);
                }
                return false;
            }
            !peer.read_closed || !peer.output.is_empty() || self.pending.iter().any(|(_, reply)| {
                matches!(reply, PendingReply::Tcp { peer: id, .. } if *id == peer.id)
            })
        });
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn schedule(&mut self, now: Instant, delay: Duration, reply: PendingReply) -> io::Result<()> {
        let deadline = now
            .checked_add(delay)
            .ok_or_else(|| io::Error::other("DNS reply deadline overflow"))?;
        self.pending.push_back((deadline, reply));
        Ok(())
    }
}

impl TcpPeer {
    fn read_queries(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let mut queries = Vec::new();
        let mut buffer = [0u8; 1024];
        for _ in 0..POLL_BATCH {
            if self.read_closed {
                break;
            }
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.read_closed = true;
                    if !self.input.is_empty() {
                        return Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "partial TCP DNS query",
                        ));
                    }
                    break;
                }
                Ok(size) => self.input.extend_from_slice(&buffer[..size]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            while self.input.len() >= 2 {
                let length = usize::from(u16::from_be_bytes([self.input[0], self.input[1]]));
                if length == 0 || length > 4096 {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "invalid TCP DNS query length",
                    ));
                }
                if self.input.len() < length + 2 {
                    break;
                }
                queries.push(self.input[2..length + 2].to_vec());
                self.input.drain(..length + 2);
            }
        }
        Ok(queries)
    }

    fn flush(&mut self) -> io::Result<()> {
        for _ in 0..POLL_BATCH {
            let Some(bytes) = self.output.front() else {
                break;
            };
            match self.stream.write(&bytes[self.written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "TCP DNS peer stopped reading",
                    ));
                }
                Ok(size) => {
                    self.written += size;
                    if self.written == bytes.len() {
                        drop(self.output.pop_front());
                        self.written = 0;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn peer_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
            | ErrorKind::InvalidData
            | ErrorKind::WriteZero
    )
}

fn reply(query: &[u8], tcp: bool, state: &mut DnsState) -> Option<(Duration, Vec<u8>)> {
    let plan = &mut state.plan;
    let step = if plan.steps.len() > 1 {
        plan.steps.pop_front()?
    } else {
        plan.steps.front()?.clone()
    };
    let rotate_at = plan.rotate_at;
    let response = match &step.action {
        DnsAction::Drop if !tcp => {
            state.dropped = state.dropped.saturating_add(1);
            None
        }
        DnsAction::Drop => build_response(query, &[], &[], false, false, plan.ttl),
        DnsAction::Truncate { .. } if !tcp => {
            build_response(query, &[], &[], true, false, plan.ttl)
        }
        DnsAction::Truncate { v4, v6 } | DnsAction::Answer { v4, v6 } => {
            build_response(query, v4, v6, false, false, plan.ttl)
        }
        DnsAction::Rotate { v4 } => {
            if v4.is_empty() {
                build_response(query, &[], &[], false, false, plan.ttl)
            } else {
                let address = v4[rotate_at % v4.len()];
                plan.rotate_at = rotate_at.wrapping_add(1);
                build_response(query, &[address], &[], false, false, plan.ttl)
            }
        }
        DnsAction::NxDomain => build_response(query, &[], &[], false, true, plan.ttl),
        DnsAction::Family { v4 } => {
            let end = question_end(query)?;
            let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
            if qtype == 28 && !tcp {
                state.dropped = state.dropped.saturating_add(1);
                None
            } else if qtype == 1 && !tcp {
                build_response(query, &[], &[], true, false, plan.ttl)
            } else {
                build_response(query, v4, &[], false, false, plan.ttl)
            }
        }
    };
    response.map(|bytes| (step.delay, bytes))
}

fn build_response(
    query: &[u8],
    v4: &[Ipv4Addr],
    v6: &[Ipv6Addr],
    truncated: bool,
    nxdomain: bool,
    ttl: u32,
) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) == 0 {
        return None;
    }
    let end = question_end(query)?;
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    let records: Vec<Vec<u8>> = if truncated {
        Vec::new()
    } else if qtype == 1 {
        v4.iter().map(|ip| record(1, &ip.octets(), ttl)).collect()
    } else if qtype == 28 {
        v6.iter().map(|ip| record(28, &ip.octets(), ttl)).collect()
    } else {
        Vec::new()
    };
    let mut flags0 = 0x84 | (query[2] & 0x01);
    if truncated {
        flags0 |= 0x02;
    }
    let flags1 = 0x80 | (u8::from(nxdomain) * 3);
    let mut out = Vec::with_capacity(end + records.len() * 28);
    out.extend_from_slice(&query[..2]);
    out.push(flags0);
    out.push(flags1);
    out.extend_from_slice(&query[4..6]);
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..end]);
    for record in records {
        out.extend_from_slice(&record);
    }
    Some(out)
}

fn record(kind: u16, data: &[u8], ttl: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12 + data.len());
    bytes.extend_from_slice(&[0xc0, 0x0c]);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0x00, 0x01]);
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

fn question_end(message: &[u8]) -> Option<usize> {
    let mut offset = 12usize;
    let mut hops = 0u8;
    loop {
        if offset >= message.len() || hops > 16 {
            return None;
        }
        let label = message[offset];
        if label == 0 {
            offset += 1;
            break;
        }
        if label & 0xc0 == 0xc0 {
            offset += 2;
            break;
        }
        offset += 1 + usize::from(label);
        hops += 1;
    }
    (offset + 4 <= message.len()).then_some(offset + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u8) -> Vec<u8> {
        vec![0, id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]
    }

    #[test]
    fn integration_scenario_udp_deadlines_do_not_block_later_replies() -> io::Result<()> {
        let _exclusive = super::super::exclusive();
        poll_all()?;
        let registered = RESPONDERS.with(|states| states.borrow().len());
        let dns = MockDns::spawn(
            DnsPlan::answer(vec![Ipv4Addr::LOCALHOST])
                .delay(Duration::from_secs(3600))
                .then(DnsAction::Answer {
                    v4: vec![Ipv4Addr::LOCALHOST],
                    v6: Vec::new(),
                }),
        )?;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_nonblocking(true)?;
        socket.send_to(&query(1), (Ipv4Addr::LOCALHOST, dns.udp_port))?;
        socket.send_to(&query(2), (Ipv4Addr::LOCALHOST, dns.udp_port))?;
        poll_all()?;
        let mut bytes = [0; 512];
        let (size, _) = socket.recv_from(&mut bytes)?;
        assert!(size > 19);
        assert_eq!(bytes[1], 2);
        assert_eq!(dns.udp_queries(), 2);
        assert_eq!(
            socket.recv_from(&mut bytes).err().map(|error| error.kind()),
            Some(ErrorKind::WouldBlock)
        );
        dns.set_plan(DnsPlan::script(DnsAction::Drop));
        socket.send_to(&query(3), (Ipv4Addr::LOCALHOST, dns.udp_port))?;
        poll_all()?;
        assert_eq!(dns.dropped(), 1);
        dns.state
            .borrow_mut()
            .poll(Instant::now() + Duration::from_secs(3601))?;
        let (size, _) = socket.recv_from(&mut bytes)?;
        assert!(size > 19);
        assert_eq!(bytes[1], 1);
        drop(dns);
        poll_all()?;
        assert_eq!(RESPONDERS.with(|states| states.borrow().len()), registered);
        Ok(())
    }

    fn tcp_response(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => bytes.push(byte[0]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    poll_all()?;
                }
                Err(error) => return Err(error),
            }
            if bytes.len() >= 2
                && bytes.len() == usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) + 2
            {
                return Ok(bytes);
            }
        }
        Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "missing TCP DNS response",
        ))
    }

    #[test]
    fn integration_lifecycle_tcp_fragments_pipeline_and_delayed_half_close() -> io::Result<()> {
        let _exclusive = super::super::exclusive();
        let dns = MockDns::spawn(
            DnsPlan::answer(vec![Ipv4Addr::LOCALHOST]).delay(Duration::from_secs(3600)),
        )?;
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, dns.tcp_port))?;
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        let request = query(1);
        let prefix = (request.len() as u16).to_be_bytes();
        stream.write_all(&prefix[..1])?;
        poll_all()?;
        stream.write_all(&prefix[1..])?;
        stream.write_all(&request[..3])?;
        poll_all()?;
        assert_eq!(dns.tcp_queries(), 0);
        stream.write_all(&request[3..])?;
        poll_all()?;
        assert_eq!(dns.tcp_queries(), 1);
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).err().map(|error| error.kind()),
            Some(ErrorKind::WouldBlock)
        );
        dns.set_plan(DnsPlan::answer(vec![Ipv4Addr::LOCALHOST]));
        stream.write_all(&prefix)?;
        stream.write_all(&query(2))?;
        poll_all()?;
        assert_eq!(dns.tcp_queries(), 2);
        assert_eq!(tcp_response(&mut stream)?[3], 2);
        stream.shutdown(std::net::Shutdown::Write)?;
        dns.state
            .borrow_mut()
            .poll(Instant::now() + Duration::from_secs(3601))?;
        assert_eq!(tcp_response(&mut stream)?[3], 1);
        assert!(dns.state.borrow().peers.is_empty());
        Ok(())
    }
}
