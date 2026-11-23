//! The bridge: owns the RakNet listener, the player sessions and the translator registry, and is
//! driven once per server tick (a WASM plugin has no threads; see `lib.rs`).
//!
//! Per tick: poll UDP -> advance Bedrock handshakes/translators -> poll the Java links ->
//! translate Java packets -> batch + flush Bedrock output -> flush RakNet.
//! No step may panic or block on peer-controlled data; every failure ends only the affected session.

mod join;
mod session;
mod translate;

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::bedrock::login::ChainVerifier;
use crate::bedrock::{self, crypto, id, play_status};
use crate::config::{AuthMode, Config};
use crate::java::forwarding::{self, ForwardProfile};
use crate::java::{JavaClient, JavaEvent, JavaIds};
use crate::raknet::{RakEvent, RakServer, RakServerConfig};
use crate::util::{Error, Reader, Result};

use join::{JoinSequence, NotImplemented};
use session::{Session, SessionState};
use translate::{Ctx, Registry};

pub struct Bridge {
    cfg: Config,
    ids: JavaIds,
    secret: Vec<u8>,
    java_addr: SocketAddrV4,
    verifier: ChainVerifier,
    rak: RakServer,
    sessions: HashMap<SocketAddrV4, Session>,
    registry: Registry,
    join: Box<dyn JoinSequence>,
    ticks: u64,
}

impl Bridge {
    pub fn start(cfg: Config, ids: JavaIds) -> Result<Self> {
        cfg.validate()?;
        let bind: SocketAddrV4 =
            cfg.bedrock.bind_address.parse().map_err(|_| Error::Invalid("bedrock.bind_address"))?;
        let java_addr: SocketAddrV4 = cfg.java.address.parse().map_err(|_| Error::Invalid("java.address"))?;
        let verifier = ChainVerifier::new(cfg.auth.mode == AuthMode::Online, &cfg.auth.mojang_root_public_keys)?;
        if cfg.auth.mode == AuthMode::Offline {
            warn!("auth.mode = \"offline\": Bedrock identities are NOT verified. Anyone can impersonate any player.");
        }
        let rak = RakServer::bind(RakServerConfig {
            bind,
            max_mtu: cfg.bedrock.max_mtu as usize,
            max_sessions: cfg.limits.max_sessions,
            max_sessions_per_ip: cfg.limits.max_sessions_per_ip,
        })?;
        info!("Bedrock listener on {bind}, Java link to {java_addr}");

        let mut bridge = Self {
            secret: cfg.java.forwarding_secret.clone().into_bytes(),
            join: Box::new(NotImplemented { protocol: cfg.bedrock.protocol }),
            cfg,
            ids,
            java_addr,
            verifier,
            rak,
            sessions: HashMap::new(),
            registry: Registry::with_defaults(),
            ticks: 0,
        };
        bridge.refresh_pong();
        Ok(bridge)
    }

    pub fn shutdown(&mut self) {
        for s in self.sessions.values_mut() {
            s.kick("Server shutting down");
        }
        self.flush_sessions();
        self.rak.flush(Instant::now());
    }

    pub fn tick(&mut self) {
        let now = Instant::now();
        self.ticks += 1;

        let mut events = Vec::new();
        self.rak.poll(now, &mut events);
        for ev in events {
            match ev {
                RakEvent::Connected(addr) => self.on_connect(addr, now),
                RakEvent::Packet(addr, data) => self.on_batch(addr, &data),
                RakEvent::Disconnected(addr, reason) => {
                    if self.sessions.remove(&addr).is_some() {
                        debug!("{addr} left: {reason}");
                    }
                }
            }
        }
        self.poll_java();
        self.expire_stalled(now);
        self.flush_sessions();
        self.rak.flush(now);
        if self.ticks % 100 == 0 {
            self.refresh_pong();
        }
    }

    fn refresh_pong(&mut self) {
        let c = &self.cfg.bedrock;
        let clean = |s: &str| s.replace(';', " ");
        let port = self.cfg.bedrock.bind_address.rsplit(':').next().unwrap_or("19132").to_owned();
        let pong = format!(
            "MCPE;{};{};{};{};{};{};{};Survival;1;{port};{port};",
            clean(&c.motd),
            c.protocol,
            clean(&c.game_version),
            self.sessions.len(),
            c.max_players,
            self.rak.guid(),
            clean(&c.sub_motd),
        );
        self.rak.set_pong(pong);
    }

    // ------------------------------------------------------------ session lifecycle

    fn on_connect(&mut self, addr: SocketAddrV4, now: Instant) {
        if self.sessions.len() >= self.cfg.limits.max_sessions {
            self.rak.disconnect(addr);
            return;
        }
        self.sessions.insert(
            addr,
            Session::new(addr, now, self.cfg.limits.max_batch_bytes, self.cfg.limits.max_queued_bytes_per_session),
        );
    }

    fn session_mut(&mut self, addr: SocketAddrV4) -> Result<&mut Session> {
        self.sessions.get_mut(&addr).ok_or_else(|| Error::Protocol("unknown session".into()))
    }

    fn fail(&mut self, addr: SocketAddrV4, message: &str) {
        if let Some(s) = self.sessions.get_mut(&addr) {
            s.kick(message);
        }
    }

    fn expire_stalled(&mut self, now: Instant) {
        let limit = Duration::from_secs(self.cfg.limits.login_timeout_secs);
        for s in self.sessions.values_mut() {
            if s.state != SessionState::InGame && now.duration_since(s.created) > limit {
                s.kick("Login timed out");
            }
        }
    }

    /// Encode and hand over everything queued for one session. Called mid-handshake where a packet
    /// must leave *before* a codec change (NetworkSettings before compression, handshake before encryption).
    fn flush_session(&mut self, addr: SocketAddrV4) -> Result<()> {
        let max = self.cfg.limits.max_batch_bytes / 4;
        let Some(s) = self.sessions.get_mut(&addr) else {
            return Ok(());
        };
        if !s.has_pending() {
            return Ok(());
        }
        let mut chunk: Vec<Vec<u8>> = Vec::new();
        let mut size = 0usize;
        for p in s.take_pending() {
            if size + p.len() > max && !chunk.is_empty() {
                let payload = s.codec.encode(&chunk)?;
                self.rak.send_game(addr, payload);
                chunk.clear();
                size = 0;
            }
            size += p.len();
            chunk.push(p);
        }
        if !chunk.is_empty() {
            let payload = s.codec.encode(&chunk)?;
            self.rak.send_game(addr, payload);
        }
        Ok(())
    }

    fn flush_sessions(&mut self) {
        let addrs: Vec<SocketAddrV4> = self.sessions.keys().copied().collect();
        for addr in addrs {
            if let Err(e) = self.flush_session(addr) {
                warn!("{addr}: flush failed: {e}");
                if let Some(s) = self.sessions.get_mut(&addr) {
                    s.close_reason.get_or_insert_with(|| "internal error".into());
                }
            }
            let closing = self.sessions.get(&addr).is_some_and(|s| s.close_reason.is_some());
            if closing {
                self.rak.disconnect(addr);
                if let Some(s) = self.sessions.remove(&addr) {
                    info!("{addr} ({}) disconnected: {}", s.java_name, s.close_reason.unwrap_or_default());
                }
            }
        }
    }

    // ------------------------------------------------------------ Bedrock -> bridge

    fn on_batch(&mut self, addr: SocketAddrV4, data: &[u8]) {
        let decoded = match self.sessions.get_mut(&addr) {
            Some(s) => s.codec.decode(data),
            None => return,
        };
        let packets = match decoded {
            Ok(p) => p,
            Err(e) => {
                debug!("bad batch from {addr}: {e}");
                self.fail(addr, "Malformed packet");
                return;
            }
        };
        for raw in packets {
            if let Err(e) = self.on_packet(addr, &raw) {
                warn!("{addr}: {e}");
                self.fail(addr, &user_message(&e));
                break;
            }
            if self.sessions.get(&addr).is_none_or(|s| s.close_reason.is_some()) {
                break;
            }
        }
    }

    fn on_packet(&mut self, addr: SocketAddrV4, raw: &[u8]) -> Result<()> {
        let mut r = Reader::new(raw);
        let pid = r.var_u32()? & 0x3ff;
        let Some(state) = self.sessions.get(&addr).map(|s| s.state) else {
            return Ok(());
        };
        match state {
            SessionState::AwaitNetworkSettings if pid == id::REQUEST_NETWORK_SETTINGS => {
                self.on_request_network_settings(addr, &mut r)
            }
            SessionState::AwaitLogin if pid == id::LOGIN => self.on_login(addr, &mut r),
            SessionState::AwaitHandshake if pid == id::CLIENT_TO_SERVER_HANDSHAKE => self.complete_login(addr),
            SessionState::Joining => {
                let Some(s) = self.sessions.get_mut(&addr) else {
                    return Ok(());
                };
                self.join.on_packet(s, pid, &mut r)
            }
            SessionState::InGame => {
                let Some(s) = self.sessions.get_mut(&addr) else {
                    return Ok(());
                };
                if let Some(handler) = self.registry.bedrock(pid) {
                    handler.run(&mut Ctx { session: s, ids: &self.ids }, &mut r)?;
                }
                Ok(())
            }
            _ => Ok(()), // out-of-order packet for this state: ignore
        }
    }

    fn on_request_network_settings(&mut self, addr: SocketAddrV4, r: &mut Reader) -> Result<()> {
        let client_protocol = r.i32_be()?;
        let supported = self.cfg.bedrock.protocol;
        let threshold = self.cfg.bedrock.compression_threshold;
        {
            let s = self.session_mut(addr)?;
            s.protocol = client_protocol;
            if client_protocol != supported {
                let status = if client_protocol < supported {
                    play_status::FAILED_CLIENT_OLD
                } else {
                    play_status::FAILED_SERVER_OLD
                };
                s.queue(id::PLAY_STATUS, &bedrock::play_status_body(status))?;
                s.close_reason = Some("unsupported Bedrock protocol version".into());
                return Ok(());
            }
            s.queue(id::NETWORK_SETTINGS, &bedrock::network_settings_body(threshold))?;
        }
        // NetworkSettings itself must travel uncompressed; compression starts with the next batch.
        self.flush_session(addr)?;
        let s = self.session_mut(addr)?;
        s.codec.enable_compression(threshold as usize);
        s.state = SessionState::AwaitLogin;
        Ok(())
    }

    fn on_login(&mut self, addr: SocketAddrV4, r: &mut Reader) -> Result<()> {
        let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let data = self.verifier.parse(r.rest(), now_unix)?;
        if data.protocol != self.cfg.bedrock.protocol {
            return Err(Error::Protocol("protocol changed between packets".into()));
        }
        let online = self.cfg.auth.mode == AuthMode::Online;
        let xuid = data.identity.xuid.clone();

        let uuid = if xuid.is_empty() {
            if online {
                return Err(Error::Auth("account has no XUID".into()));
            }
            offline_uuid(&data.identity.display_name)
        } else {
            forwarding::uuid_from_xuid(&xuid)?
        };
        let duplicate = !xuid.is_empty()
            && self
                .sessions
                .values()
                .any(|o| o.addr != addr && o.identity.as_ref().is_some_and(|i| i.xuid == xuid));
        if duplicate {
            return Err(Error::Auth("this account is already connected".into()));
        }

        let name = self.unique_java_name(&data.identity.display_name)?;
        let profile = ForwardProfile { name: name.clone(), uuid, ip: addr.ip().to_string() };
        let java = JavaClient::connect(self.java_addr, profile, self.secret.clone(), self.cfg.java.protocol_version)?;
        info!("{addr} logged in as {} (java name {name}, verified: {})", data.identity.display_name, data.identity.verified);

        let key = data.identity.client_key.clone();
        {
            let s = self.session_mut(addr)?;
            s.java_name = name;
            s.client = data.client;
            s.identity = Some(data.identity);
            s.java = Some(java);
        }

        if self.cfg.auth.encryption {
            let (jwt, cipher) = crypto::start_handshake(&key)?;
            {
                let s = self.session_mut(addr)?;
                s.queue(id::SERVER_TO_CLIENT_HANDSHAKE, &bedrock::server_to_client_handshake_body(&jwt))?;
                s.state = SessionState::AwaitHandshake;
            }
            // The handshake packet is the last unencrypted one.
            self.flush_session(addr)?;
            self.session_mut(addr)?.codec.cipher = Some(cipher);
            Ok(())
        } else {
            self.complete_login(addr)
        }
    }

    fn complete_login(&mut self, addr: SocketAddrV4) -> Result<()> {
        let Some(s) = self.sessions.get_mut(&addr) else {
            return Err(Error::Protocol("unknown session".into()));
        };
        s.queue(id::PLAY_STATUS, &bedrock::play_status_body(play_status::LOGIN_SUCCESS))?;
        s.state = SessionState::Joining;
        self.join.begin(s)
    }

    fn unique_java_name(&self, display: &str) -> Result<String> {
        let base = sanitize_name(&self.cfg.auth.username_prefix, display);
        let mut name = base.clone();
        let mut n = 1u32;
        while self.sessions.values().any(|s| s.java_name == name) {
            if n > 99 {
                return Err(Error::Auth("too many players with the same name".into()));
            }
            let suffix = n.to_string();
            let keep = 16usize.saturating_sub(suffix.len());
            name = format!("{}{}", base.chars().take(keep).collect::<String>(), suffix);
            n += 1;
        }
        Ok(name)
    }

    // ------------------------------------------------------------ Java -> bridge

    fn poll_java(&mut self) {
        let mut pending: Vec<(SocketAddrV4, Vec<JavaEvent>)> = Vec::new();
        for (addr, s) in self.sessions.iter_mut() {
            if let Some(java) = s.java.as_mut() {
                let mut events = Vec::new();
                java.poll(&self.ids, &mut events);
                if !events.is_empty() {
                    pending.push((*addr, events));
                }
            }
        }
        for (addr, events) in pending {
            for ev in events {
                match ev {
                    JavaEvent::Closed(reason) => {
                        debug!("{addr}: java link closed: {reason}");
                        self.fail(addr, "Lost connection to the server");
                    }
                    JavaEvent::Play { name, body } => self.dispatch_java(addr, &name, &body),
                }
            }
        }
    }

    fn dispatch_java(&mut self, addr: SocketAddrV4, name: &str, body: &[u8]) {
        let Some(s) = self.sessions.get_mut(&addr) else {
            return;
        };
        if s.state != SessionState::InGame {
            return;
        }
        if let Some(handler) = self.registry.java(name) {
            let mut r = Reader::new(body);
            if let Err(e) = handler.run(&mut Ctx { session: s, ids: &self.ids }, &mut r) {
                debug!("{addr}: translating java packet {name} failed: {e}");
            }
        }
    }
}

fn user_message(e: &Error) -> String {
    match e {
        Error::Auth(m) => format!("Login failed: {m}"),
        _ => "Internal bridge error".to_owned(),
    }
}

/// Java-legal name (`[A-Za-z0-9_]`, max 16) with the configured prefix.
fn sanitize_name(prefix: &str, display: &str) -> String {
    let mut name = prefix.to_owned();
    for c in display.chars() {
        if name.chars().count() >= 16 {
            break;
        }
        if c.is_ascii_alphanumeric() || c == '_' {
            name.push(c);
        } else if c == ' ' {
            name.push('_');
        }
    }
    if name == prefix {
        name.push_str("Player");
    }
    name
}

/// Stable UUID for unauthenticated (offline) logins.
fn offline_uuid(name: &str) -> [u8; 16] {
    let digest = Sha256::digest(format!("bedrock-bridge-offline:{name}").as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_java_legal_and_bounded() {
        assert_eq!(sanitize_name(".", "Steve Jobs"), ".Steve_Jobs");
        assert_eq!(sanitize_name(".", "日本語"), ".Player");
        assert!(sanitize_name(".", "ABCDEFGHIJKLMNOPQRSTUVWXYZ").chars().count() <= 16);
    }
}
