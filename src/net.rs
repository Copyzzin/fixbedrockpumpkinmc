//! Non-blocking sockets on top of WASI 0.2 (`wasi:sockets`).
//!
//! A WASM plugin has no threads and no async runtime, so everything here is
//! "poll once per tick": `receive` / `read` return immediately (possibly empty) and
//! writes are queued and drained as the host grants budget.
//!
//! The host only links these imports when the plugin was granted the matching
//! `network.*` permissions in `PluginMetadata` (see `lib.rs`).

use std::net::{Ipv4Addr, SocketAddrV4};

use wasi::io::streams::{InputStream, OutputStream, StreamError};
use wasi::sockets::instance_network::instance_network;
use wasi::sockets::network::{ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress};
use wasi::sockets::tcp::TcpSocket;
use wasi::sockets::tcp_create_socket::create_tcp_socket;
use wasi::sockets::udp::{IncomingDatagramStream, OutgoingDatagram, OutgoingDatagramStream, UdpSocket};
use wasi::sockets::udp_create_socket::create_udp_socket;

use crate::util::{Error, Result, io_err};

/// Upper bound for bytes queued towards one TCP peer (back-pressure, see `queue`).
const MAX_TCP_OUT: usize = 8 * 1024 * 1024;

fn to_wasi(a: SocketAddrV4) -> IpSocketAddress {
    let o = a.ip().octets();
    IpSocketAddress::Ipv4(Ipv4SocketAddress { port: a.port(), address: (o[0], o[1], o[2], o[3]) })
}

fn from_wasi(a: &IpSocketAddress) -> Option<SocketAddrV4> {
    match a {
        IpSocketAddress::Ipv4(v) => Some(SocketAddrV4::new(
            Ipv4Addr::new(v.address.0, v.address.1, v.address.2, v.address.3),
            v.port,
        )),
        // IPv6 (Bedrock port 19133) is not supported yet.
        IpSocketAddress::Ipv6(_) => None,
    }
}

/// Unconnected UDP socket (one local port, many peers) used by the RakNet server.
pub struct UdpEndpoint {
    _socket: UdpSocket,
    rx: IncomingDatagramStream,
    tx: OutgoingDatagramStream,
}

impl UdpEndpoint {
    pub fn bind(addr: SocketAddrV4) -> Result<Self> {
        let network = instance_network();
        let socket = create_udp_socket(IpAddressFamily::Ipv4).map_err(io_err)?;
        socket.start_bind(&network, to_wasi(addr)).map_err(io_err)?;
        // Binding is two-phase in WASI; block once at startup until it completes.
        socket.subscribe().block();
        socket.finish_bind().map_err(io_err)?;
        let (rx, tx) = socket.stream(None).map_err(io_err)?;
        Ok(Self { _socket: socket, rx, tx })
    }

    /// Drain up to `max` pending datagrams. Never blocks.
    pub fn recv(&self, max: u64) -> Vec<(SocketAddrV4, Vec<u8>)> {
        match self.rx.receive(max) {
            Ok(list) => list
                .into_iter()
                .filter_map(|d| from_wasi(&d.remote_address).map(|a| (a, d.data)))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Send one datagram. UDP is lossy by contract: a full host buffer is an error
    /// the caller may ignore (RakNet's reliability layer resends).
    pub fn send(&self, to: SocketAddrV4, data: Vec<u8>) -> Result<()> {
        let budget = self.tx.check_send().map_err(io_err)?;
        if budget == 0 {
            return Err(Error::Io("udp send buffer full".into()));
        }
        self.tx
            .send(&[OutgoingDatagram { data, remote_address: Some(to_wasi(to)) }])
            .map_err(io_err)?;
        Ok(())
    }
}

enum Conn {
    Connecting,
    Open { rx: InputStream, tx: OutputStream },
    Closed,
}

/// Non-blocking outbound TCP connection (the link from the bridge to Pumpkin's Java port).
pub struct TcpClient {
    socket: TcpSocket,
    conn: Conn,
    out: Vec<u8>,
}

impl TcpClient {
    pub fn connect(addr: SocketAddrV4) -> Result<Self> {
        let network = instance_network();
        let socket = create_tcp_socket(IpAddressFamily::Ipv4).map_err(io_err)?;
        socket.start_connect(&network, to_wasi(addr)).map_err(io_err)?;
        Ok(Self { socket, conn: Conn::Connecting, out: Vec::new() })
    }

    /// Returns `Ok(true)` once the connection is established.
    pub fn poll_connect(&mut self) -> Result<bool> {
        if matches!(self.conn, Conn::Open { .. }) {
            return Ok(true);
        }
        if matches!(self.conn, Conn::Closed) {
            return Err(Error::Io("connection closed".into()));
        }
        match self.socket.finish_connect() {
            Ok((rx, tx)) => {
                self.conn = Conn::Open { rx, tx };
                Ok(true)
            }
            Err(ErrorCode::WouldBlock) => Ok(false),
            Err(e) => {
                self.conn = Conn::Closed;
                Err(io_err(e))
            }
        }
    }

    /// Read whatever is available (possibly nothing). EOF is reported as an error.
    pub fn read(&mut self, max: u64) -> Result<Vec<u8>> {
        let result = match &self.conn {
            Conn::Open { rx, .. } => rx.read(max),
            _ => return Ok(Vec::new()),
        };
        match result {
            Ok(data) => Ok(data),
            Err(StreamError::Closed) => {
                self.conn = Conn::Closed;
                Err(Error::Io("connection closed by peer".into()))
            }
            Err(e) => {
                self.conn = Conn::Closed;
                Err(io_err(e))
            }
        }
    }

    /// Queue bytes for sending; fails (instead of growing without bound) when the peer is too slow.
    pub fn queue(&mut self, data: &[u8]) -> Result<()> {
        if self.out.len() + data.len() > MAX_TCP_OUT {
            return Err(Error::Limit("tcp send queue"));
        }
        self.out.extend_from_slice(data);
        Ok(())
    }

    /// Drain the queue as far as the host's write budget allows.
    pub fn flush(&mut self) -> Result<()> {
        let Conn::Open { tx, .. } = &self.conn else {
            return Ok(());
        };
        while !self.out.is_empty() {
            let budget = tx.check_write().map_err(io_err)? as usize;
            if budget == 0 {
                break;
            }
            let n = budget.min(self.out.len()).min(64 * 1024);
            tx.write(&self.out[..n]).map_err(io_err)?;
            self.out.drain(..n);
        }
        Ok(())
    }
}
