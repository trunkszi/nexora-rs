//! Cleartext HTTP/1.1 keep-alive against one listener.
//!
//! `app.local` is not pinned. c-ares queries the loopback responder started
//! below; that responder answers `A` with `127.0.0.1` and `AAAA` with NODATA.
//! Each drive turn advances its nonblocking UDP and TCP sockets on the same thread.
//! The client polls the shared ring. [`nexora::HttpServer::drive`] only applies
//! completions that poll already recorded.

use std::{
    cell::Cell,
    collections::VecDeque,
    io::{ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    rc::Rc,
    time::{Duration, Instant},
};

use nexora::{
    ClientConfig, Error, HttpClient, HttpServer, HttpService, OriginKey, Proactor, Request,
    RequestContext, Responder, Response, Scheme, ServerConfig, StatusCode, SubsystemId,
};

struct Echo;

impl HttpService for Echo {
    /// Replies `ok` and leaves the connection reusable.
    ///
    /// # Errors
    /// Returns a responder error when the connection is already closed.
    ///
    /// # Panics
    /// This method does not panic.
    fn call(
        &mut self,
        _ctx: &mut RequestContext,
        _req: Request,
        responder: Responder,
    ) -> nexora::Result<()> {
        responder.respond(Response::text(StatusCode::OK, "ok"))
    }
}

const MAX_DNS_QUERY: usize = 4096;
const MAX_DNS_PEERS: usize = 32;

struct LocalDns {
    csv: String,
    udp: UdpSocket,
    tcp: TcpListener,
    queries: Cell<usize>,
    pending: VecDeque<(Vec<u8>, SocketAddr)>,
    peers: Vec<DnsTcp>,
}

impl LocalDns {
    fn new() -> nexora::Result<Self> {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let csv = format!(
            "dns://127.0.0.1:{}?tcpport={}",
            udp.local_addr()?.port(),
            tcp.local_addr()?.port()
        );
        Ok(Self {
            csv,
            udp,
            tcp,
            queries: Cell::new(0),
            pending: VecDeque::new(),
            peers: Vec::new(),
        })
    }

    fn queries(&self) -> usize {
        self.queries.get()
    }

    fn poll(&mut self) -> nexora::Result<()> {
        self.flush_udp()?;
        let mut buffer = [0; MAX_DNS_QUERY];
        for _ in self.pending.len()..MAX_DNS_PEERS {
            let (size, peer) = match self.udp.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(error) if is_pause(&error) => break,
                Err(error) => return Err(error.into()),
            };
            self.queries.set(self.queries.get().saturating_add(1));
            if let Some(response) = dns_reply(&buffer[..size]) {
                self.pending.push_back((response, peer));
            }
        }
        self.flush_udp()?;
        for _ in self.peers.len()..MAX_DNS_PEERS {
            let stream = match self.tcp.accept() {
                Ok((stream, _)) => stream,
                Err(error) if is_pause(&error) => break,
                Err(error) => return Err(error.into()),
            };
            stream.set_nonblocking(true)?;
            self.peers.push(DnsTcp {
                stream,
                input: Vec::new(),
                output: Vec::new(),
                written: 0,
            });
        }
        let mut index = 0;
        while index < self.peers.len() {
            match self.peers[index].poll(&self.queries) {
                Ok(true) => index += 1,
                Ok(false) => {
                    self.peers.swap_remove(index);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::NotConnected
                    ) =>
                {
                    self.peers.swap_remove(index);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn flush_udp(&mut self) -> std::io::Result<()> {
        while let Some((response, peer)) = self.pending.front() {
            match self.udp.send_to(response, peer) {
                Ok(size) if size == response.len() => {
                    self.pending.pop_front();
                }
                Ok(_) => {
                    return Err(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "partial DNS datagram",
                    ));
                }
                Err(error) if is_pause(&error) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

struct DnsTcp {
    stream: TcpStream,
    input: Vec<u8>,
    output: Vec<u8>,
    written: usize,
}

impl DnsTcp {
    fn message_len(&self) -> std::io::Result<Option<usize>> {
        if self.input.len() < 2 {
            return Ok(None);
        }
        let size = usize::from(u16::from_be_bytes([self.input[0], self.input[1]]));
        if size == 0 || size > MAX_DNS_QUERY {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "invalid DNS TCP length",
            ));
        }
        Ok(Some(size + 2))
    }

    fn poll(&mut self, queries: &Cell<usize>) -> std::io::Result<bool> {
        self.flush()?;
        if !self.output.is_empty() {
            return Ok(true);
        }
        if self.message_len()?.is_none_or(|end| self.input.len() < end) {
            let mut buffer = [0; 1024];
            let room = buffer.len().min(MAX_DNS_QUERY + 2 - self.input.len());
            match self.stream.read(&mut buffer[..room]) {
                Ok(0) => return Ok(false),
                Ok(size) => self.input.extend_from_slice(&buffer[..size]),
                Err(error) if is_pause(&error) => return Ok(true),
                Err(error) => return Err(error),
            }
        }
        let Some(end) = self.message_len()? else {
            return Ok(true);
        };
        if self.input.len() < end {
            return Ok(true);
        }
        queries.set(queries.get().saturating_add(1));
        let Some(response) = dns_reply(&self.input[2..end]) else {
            return Ok(false);
        };
        drop(self.input.drain(..end));
        let length = u16::try_from(response.len())
            .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "DNS response too large"))?;
        self.output.extend_from_slice(&length.to_be_bytes());
        self.output.extend_from_slice(&response);
        self.flush()?;
        Ok(true)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        while self.written < self.output.len() {
            match self.stream.write(&self.output[self.written..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "DNS TCP write stalled",
                    ));
                }
                Ok(size) => self.written += size,
                Err(error) if is_pause(&error) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        self.output.clear();
        self.written = 0;
        Ok(())
    }
}

fn main() -> nexora::Result<()> {
    let mut dns = LocalDns::new()?;
    let mut proactor = Proactor::builder().build()?;
    let server_config = ServerConfig {
        net_subsystem: SubsystemId::new_unchecked(3),
        ..ServerConfig::default()
    };
    let mut server = HttpServer::bind(
        &mut proactor,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_config,
        Echo,
    )?;
    let port = server.local_addr().port();
    let client_config = ClientConfig {
        net_subsystem: SubsystemId::new_unchecked(1),
        dns_subsystem: SubsystemId::new_unchecked(2),
        prefer_http2: false,
        http2_prior_knowledge: false,
        dns_servers_csv: Some(dns.csv.clone()),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        ..ClientConfig::default()
    };
    let mut client = HttpClient::new(&mut proactor, client_config)?;
    let count = Rc::new(Cell::new(0u32));
    let bad = Rc::new(Cell::new(false));
    for _ in 0..2 {
        let callback_count = Rc::clone(&count);
        let callback_bad = Rc::clone(&bad);
        let wait = Rc::clone(&count);
        let seen = wait.get();
        let request = Request::get(&format!("http://app.local:{port}/keep"))?;
        client.submit(
            &mut proactor,
            request,
            move |_ctx, _id, result| match result {
                Ok(response) if response.body.as_ref() == b"ok" => {
                    callback_count.set(callback_count.get().saturating_add(1));
                }
                _ => callback_bad.set(true),
            },
        )?;
        drive_until(
            &mut proactor,
            &mut server,
            &mut client,
            &mut dns,
            move || wait.get() > seen,
        )?;
    }
    if bad.get() || count.get() != 2 {
        return Err(Error::InvalidState(String::from(
            "expected two HTTP/1.1 bodies of ok",
        )));
    }
    let origin = OriginKey::new(Scheme::Http, "app.local", port);
    if client.idle_connection_count(&origin) != 1 {
        return Err(Error::InvalidState(String::from(
            "keep-alive did not reuse one pooled connection",
        )));
    }
    if dns.queries() == 0 {
        return Err(Error::InvalidState(String::from(
            "app.local did not query the loopback resolver",
        )));
    }
    println!(
        "http/1.1 keep-alive ok port={port} pooled=1 dns_queries={}",
        dns.queries()
    );
    Ok(())
}

fn drive_until(
    proactor: &mut Proactor,
    server: &mut HttpServer<Echo>,
    client: &mut HttpClient,
    dns: &mut LocalDns,
    ready: impl Fn() -> bool,
) -> nexora::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        dns.poll()?;
        server.drive(proactor)?;
        client.drive_with(proactor, &mut *server)?;
        if ready() {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}

fn dns_reply(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) == 0 {
        return None;
    }
    let end = question_end(query)?;
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    let record = if qtype == 1 { Some(a_record()) } else { None };
    let mut flags0 = 0x84 | (query[2] & 0x01);
    flags0 &= 0xfd;
    let mut out = Vec::with_capacity(end.saturating_add(16));
    out.extend_from_slice(&query[..2]);
    out.push(flags0);
    out.push(0x80);
    out.extend_from_slice(&query[4..6]);
    out.extend_from_slice(&u16::from(u8::from(record.is_some())).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..end]);
    if let Some(record) = record {
        out.extend_from_slice(&record);
    }
    Some(out)
}

fn a_record() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
    bytes.extend_from_slice(&60u32.to_be_bytes());
    bytes.extend_from_slice(&[0x00, 0x04]);
    bytes.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
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

fn is_pause(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn query(kind: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["app", "local"] {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes());
        out
    }

    fn poll_until(
        dns: &mut LocalDns,
        mut ready: impl FnMut(&LocalDns) -> std::io::Result<bool>,
    ) -> nexora::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            dns.poll()?;
            if ready(dns)? {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    #[test]
    fn scenario_udp_answers_both_families_without_workers() -> nexora::Result<()> {
        let mut dns = LocalDns::new()?;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        client.set_nonblocking(true)?;
        for kind in [1, 28] {
            client.send_to(&query(kind), dns.udp.local_addr()?)?;
            let mut response = [0; MAX_DNS_QUERY];
            let mut received = 0;
            poll_until(&mut dns, |_| match client.recv_from(&mut response) {
                Ok((size, _)) => {
                    received = size;
                    Ok(true)
                }
                Err(error) if is_pause(&error) => Ok(false),
                Err(error) => Err(error),
            })?;
            assert_eq!(&response[..2], &[0x12, 0x34]);
            assert_ne!(response[2] & 0x80, 0);
            assert_eq!(
                u16::from_be_bytes([response[6], response[7]]),
                u16::from(kind == 1)
            );
            if kind == 1 {
                assert_eq!(
                    &response[received - 4..received],
                    &Ipv4Addr::LOCALHOST.octets()
                );
            }
        }
        assert_eq!(dns.queries(), 2);
        Ok(())
    }

    fn receive_frames(
        dns: &mut LocalDns,
        client: &mut TcpStream,
        expected: usize,
    ) -> nexora::Result<Vec<Vec<u8>>> {
        let mut input = Vec::new();
        let mut responses = Vec::new();
        poll_until(dns, |_| {
            let mut bytes = [0; 1024];
            match client.read(&mut bytes) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "DNS peer closed",
                    ));
                }
                Ok(size) => input.extend_from_slice(&bytes[..size]),
                Err(error) if is_pause(&error) => {}
                Err(error) => return Err(error),
            }
            while input.len() >= 2 {
                let size = usize::from(u16::from_be_bytes([input[0], input[1]]));
                if input.len() < size + 2 {
                    break;
                }
                responses.push(input[2..size + 2].to_vec());
                drop(input.drain(..size + 2));
            }
            Ok(responses.len() == expected)
        })?;
        Ok(responses)
    }

    #[test]
    fn lifecycle_tcp_retains_trickled_prefix_and_pipelined_queries() -> nexora::Result<()> {
        let mut dns = LocalDns::new()?;
        let mut client = TcpStream::connect(dns.tcp.local_addr()?)?;
        client.set_nonblocking(true)?;
        client.set_nodelay(true)?;
        let query = query(1);
        let mut frame = (query.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&query);
        for (index, byte) in frame.iter().enumerate() {
            assert_eq!(client.write(std::slice::from_ref(byte))?, 1);
            dns.poll()?;
            if index + 1 < frame.len() {
                assert_eq!(dns.queries(), 0);
            }
        }
        let first = receive_frames(&mut dns, &mut client, 1)?;
        assert_eq!(&first[0][..2], &[0x12, 0x34]);
        assert_eq!(
            &first[0][first[0].len() - 4..],
            &Ipv4Addr::LOCALHOST.octets()
        );
        let burst = [frame.as_slice(), frame.as_slice()].concat();
        assert_eq!(client.write(&burst)?, burst.len());
        let responses = receive_frames(&mut dns, &mut client, 2)?;
        assert_eq!(responses, vec![first[0].clone(), first[0].clone()]);
        assert_eq!(dns.queries(), 3);
        assert_eq!(dns.peers.len(), 1);
        drop(client);
        poll_until(&mut dns, |dns| Ok(dns.peers.is_empty()))?;
        assert!(dns.peers.is_empty());
        Ok(())
    }
}
