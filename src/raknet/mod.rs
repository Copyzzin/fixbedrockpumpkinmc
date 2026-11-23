//! RakNet transport used by Bedrock Edition (UDP).
//!
//! * `server`  – offline handshake (ping / open-connection 1+2) and the session table
//! * `session` – per-connection reliability layer (frames, ACK/NACK, splits, ordering)

mod server;
mod session;

pub use server::{RakEvent, RakServer, RakServerConfig};

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::util::{Error, Reader, Result, Writer};

pub const MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

/// RakNet protocol version spoken by Bedrock clients.
pub const RAKNET_PROTOCOL: u8 = 11;

/// Encode an IPv4 `SocketAddress` (version byte, bitwise-inverted octets, big-endian port).
pub(crate) fn write_addr(w: &mut Writer, a: SocketAddrV4) {
    w.u8(4);
    for o in a.ip().octets() {
        w.u8(!o);
    }
    w.u16_be(a.port());
}

/// Read a `SocketAddress`; IPv6 is parsed (to stay in sync) but mapped to `0.0.0.0`.
pub(crate) fn read_addr(r: &mut Reader) -> Result<SocketAddrV4> {
    match r.u8()? {
        4 => {
            let b = r.take(4)?;
            let port = r.u16_be()?;
            Ok(SocketAddrV4::new(Ipv4Addr::new(!b[0], !b[1], !b[2], !b[3]), port))
        }
        6 => {
            // family (2, LE) + port (2) + flow info (4) + address (16) + scope id (4)
            r.take(2)?;
            let port = r.u16_be()?;
            r.take(4 + 16 + 4)?;
            Ok(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
        }
        _ => Err(Error::Invalid("unknown address family")),
    }
}
