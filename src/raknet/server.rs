//! RakNet listener: offline handshake + session table.
//!
//! Anti-abuse: a global session cap, a per-IP cap, and a deadline for half-open sessions.
//! (Bedrock does not use RakNet's cookie/security mode, so source addresses can be spoofed;
//! these caps bound the damage instead of pretending to prevent it.)

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use tracing::debug;

use super::session::{RakSession, SessionEvent, SessionState};
use super::{MAGIC, RAKNET_PROTOCOL, read_addr, write_addr};
use crate::net::UdpEndpoint;
use crate::util::{Reader, Result, Writer, random_i64};

const MAX_DATAGRAMS_PER_POLL: u64 = 1024;
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

pub struct RakServerConfig {
    pub bind: SocketAddrV4,
    pub max_mtu: usize,
    pub max_sessions: usize,
    pub max_sessions_per_ip: usize,
}

pub enum RakEvent {
    Connected(SocketAddrV4),
    /// One Bedrock batch (bytes after the 0xFE marker).
    Packet(SocketAddrV4, Vec<u8>),
    Disconnected(SocketAddrV4, &'static str),
}

pub struct RakServer {
    endpoint: UdpEndpoint,
    guid: i64,
    cfg: RakServerConfig,
    sessions: HashMap<SocketAddrV4, RakSession>,
    pong: String,
}

impl RakServer {
    pub fn bind(cfg: RakServerConfig) -> Result<Self> {
        let endpoint = UdpEndpoint::bind(cfg.bind)?;
        Ok(Self { endpoint, guid: random_i64(), cfg, sessions: HashMap::new(), pong: String::new() })
    }

    pub fn guid(&self) -> i64 {
        self.guid
    }

    /// Server list ping payload (`MCPE;motd;protocol;version;online;max;guid;sub;mode;1;port;port;`).
    pub fn set_pong(&mut self, s: String) {
        self.pong = s;
    }

    pub fn send_game(&mut self, to: SocketAddrV4, payload: Vec<u8>) {
        if let Some(s) = self.sessions.get_mut(&to) {
            if s.send_game(payload).is_err() {
                debug!("dropping session {to}: send queue overflow");
            }
        }
    }

    pub fn disconnect(&mut self, to: SocketAddrV4) {
        if let Some(s) = self.sessions.get_mut(&to) {
            s.disconnect();
        }
    }

    pub fn poll(&mut self, now: Instant, events: &mut Vec<RakEvent>) {
        for (addr, data) in self.endpoint.recv(MAX_DATAGRAMS_PER_POLL) {
            let Some(&first) = data.first() else {
                continue;
            };
            if first & 0x80 != 0 {
                let result = match self.sessions.get_mut(&addr) {
                    Some(s) => s.on_datagram(&data, now),
                    None => continue,
                };
                match result {
                    Ok(list) => {
                        for ev in list {
                            events.push(match ev {
                                SessionEvent::Connected => RakEvent::Connected(addr),
                                SessionEvent::Packet(p) => RakEvent::Packet(addr, p),
                            });
                        }
                    }
                    Err(e) => debug!("malformed datagram from {addr}: {e}"),
                }
            } else if let Err(e) = self.handle_offline(addr, &data, now) {
                debug!("malformed offline packet from {addr}: {e}");
            }
        }

        let dead: Vec<(SocketAddrV4, &'static str)> = self
            .sessions
            .iter()
            .filter_map(|(a, s)| {
                if let Some(r) = s.closed_reason() {
                    Some((*a, r))
                } else if s.timed_out(now) {
                    Some((*a, "timed out"))
                } else if s.state != SessionState::Connected
                    && now.duration_since(s.created) > HANDSHAKE_DEADLINE
                {
                    Some((*a, "handshake timed out"))
                } else {
                    None
                }
            })
            .collect();
        for (addr, reason) in dead {
            self.sessions.remove(&addr);
            events.push(RakEvent::Disconnected(addr, reason));
        }
    }

    /// Send everything the sessions have queued. Call once per tick, after the bridge has run.
    pub fn flush(&mut self, now: Instant) {
        for (addr, s) in self.sessions.iter_mut() {
            for datagram in s.flush(now) {
                let _ = self.endpoint.send(*addr, datagram);
            }
        }
    }

    fn reply(&self, to: SocketAddrV4, w: Writer) {
        let _ = self.endpoint.send(to, w.finish());
    }

    fn handle_offline(&mut self, addr: SocketAddrV4, data: &[u8], now: Instant) -> Result<()> {
        let mut r = Reader::new(&data[1..]);
        match data[0] {
            // Unconnected ping (0x01) / open ping (0x02)
            0x01 | 0x02 => {
                let time = r.i64_be()?;
                let mut w = Writer::new();
                w.u8(0x1c);
                w.i64_be(time);
                w.i64_be(self.guid);
                w.bytes(&MAGIC);
                let pong = self.pong.as_bytes();
                w.u16_be(pong.len().min(u16::MAX as usize) as u16);
                w.bytes(&pong[..pong.len().min(u16::MAX as usize)]);
                self.reply(addr, w);
            }
            // Open connection request 1
            0x05 => {
                if r.take(16)? != MAGIC {
                    return Ok(());
                }
                let protocol = r.u8()?;
                let mut w = Writer::new();
                if protocol != RAKNET_PROTOCOL {
                    w.u8(0x19);
                    w.u8(RAKNET_PROTOCOL);
                    w.bytes(&MAGIC);
                    w.i64_be(self.guid);
                } else {
                    // The request is padded up to the MTU being probed (minus IP+UDP headers).
                    let mtu = (data.len() + 28).clamp(400, self.cfg.max_mtu);
                    w.u8(0x06);
                    w.bytes(&MAGIC);
                    w.i64_be(self.guid);
                    w.u8(0); // security disabled
                    w.u16_be(mtu as u16);
                }
                self.reply(addr, w);
            }
            // Open connection request 2
            0x07 => {
                if r.take(16)? != MAGIC {
                    return Ok(());
                }
                let _server_addr = read_addr(&mut r)?;
                let mtu = (r.u16_be()? as usize).clamp(400, self.cfg.max_mtu);
                let client_guid = r.i64_be()?;

                if let Some(existing) = self.sessions.get(&addr) {
                    if existing.state == SessionState::Connected {
                        return Ok(()); // ignore spoofed resets of a live session
                    }
                } else {
                    let from_ip = self.sessions.keys().filter(|a| a.ip() == addr.ip()).count();
                    if self.sessions.len() >= self.cfg.max_sessions || from_ip >= self.cfg.max_sessions_per_ip {
                        let mut w = Writer::new();
                        w.u8(0x14); // no free incoming connections
                        w.bytes(&MAGIC);
                        w.i64_be(self.guid);
                        self.reply(addr, w);
                        return Ok(());
                    }
                }
                self.sessions.insert(addr, RakSession::new(addr, client_guid, mtu, now));
                let mut w = Writer::new();
                w.u8(0x08);
                w.bytes(&MAGIC);
                w.i64_be(self.guid);
                write_addr(&mut w, addr);
                w.u16_be(mtu as u16);
                w.u8(0); // encryption disabled at the RakNet level
                self.reply(addr, w);
            }
            _ => {}
        }
        Ok(())
    }
}
