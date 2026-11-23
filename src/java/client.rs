//! One Java-protocol client connection from the bridge to Pumpkin (the "downstream" of a Bedrock player).
//!
//! State machine: Handshake -> Login (Velocity forwarding query) -> Configuration -> Play.
//! Housekeeping the real client would do (keep-alives, pings, teleport confirmations, chunk-batch
//! acknowledgements, known-packs, finish-configuration) is answered here; everything else in Play
//! is surfaced as `JavaEvent::Play` for the translators.
//!
//! Wire layouts below follow the 1.21.5+ protocol family. Packet *ids* come from `JavaIds`, but field
//! layouts are code: when a Minecraft release changes one, this is where to adjust (each spot is small).

use std::net::SocketAddrV4;

use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;

use super::forwarding::{self, ForwardProfile};
use super::ids::{JavaIds, State};
use crate::net::TcpClient;
use crate::util::{Error, Reader, Result, Writer};

/// Vanilla limits: 2^21 bytes per compressed frame, 2^23 uncompressed.
const MAX_FRAME: usize = 2 * 1024 * 1024;
const MAX_UNCOMPRESSED: usize = 8 * 1024 * 1024;
const MAX_INBUF: usize = 4 * MAX_FRAME;

pub enum JavaEvent {
    /// A Play-state packet the translators may care about (`name` is the registry name without namespace).
    Play { name: String, body: Vec<u8> },
    Closed(String),
}

pub struct JavaClient {
    tcp: TcpClient,
    state: State,
    compression: Option<usize>,
    inbuf: Vec<u8>,
    profile: ForwardProfile,
    secret: Vec<u8>,
    protocol: i32,
    host: String,
    port: u16,
    sent_hello: bool,
    closed: bool,
}

impl JavaClient {
    pub fn connect(addr: SocketAddrV4, profile: ForwardProfile, secret: Vec<u8>, protocol: i32) -> Result<Self> {
        Ok(Self {
            tcp: TcpClient::connect(addr)?,
            state: State::Handshake,
            compression: None,
            inbuf: Vec::new(),
            profile,
            secret,
            protocol,
            host: addr.ip().to_string(),
            port: addr.port(),
            sent_hello: false,
            closed: false,
        })
    }

    pub fn in_play(&self) -> bool {
        self.state == State::Play
    }

    /// Drive the connection once. Never blocks; errors close the link and are reported as an event.
    pub fn poll(&mut self, ids: &JavaIds, events: &mut Vec<JavaEvent>) {
        if self.closed {
            return;
        }
        if let Err(e) = self.poll_inner(ids, events) {
            self.closed = true;
            events.push(JavaEvent::Closed(e.to_string()));
        }
    }

    fn poll_inner(&mut self, ids: &JavaIds, events: &mut Vec<JavaEvent>) -> Result<()> {
        if !self.tcp.poll_connect()? {
            return Ok(());
        }
        if !self.sent_hello {
            self.send_hello(ids)?;
        }
        let data = self.tcp.read(64 * 1024)?;
        self.inbuf.extend_from_slice(&data);
        if self.inbuf.len() > MAX_INBUF {
            return Err(Error::Limit("java receive buffer"));
        }
        while let Some((id, body)) = self.next_packet()? {
            self.handle(ids, id, body, events)?;
        }
        self.tcp.flush()
    }

    // ---------------------------------------------------------------- framing

    fn next_packet(&mut self) -> Result<Option<(i32, Vec<u8>)>> {
        let mut r = Reader::new(&self.inbuf);
        let len = match r.var_u32() {
            Ok(v) => v as usize,
            Err(Error::Eof) => return Ok(None),
            Err(e) => return Err(e),
        };
        let header = self.inbuf.len() - r.remaining();
        if len > MAX_FRAME {
            return Err(Error::Limit("java packet too large"));
        }
        if r.remaining() < len {
            return Ok(None);
        }
        let frame = self.inbuf[header..header + len].to_vec();
        self.inbuf.drain(..header + len);

        let body = self.decompress(frame)?;
        let mut r = Reader::new(&body);
        let id = r.var_u32()? as i32;
        Ok(Some((id, r.rest().to_vec())))
    }

    fn decompress(&self, frame: Vec<u8>) -> Result<Vec<u8>> {
        if self.compression.is_none() {
            return Ok(frame);
        }
        let mut r = Reader::new(&frame);
        let size = r.var_u32()? as usize;
        if size == 0 {
            return Ok(r.rest().to_vec());
        }
        if size > MAX_UNCOMPRESSED {
            return Err(Error::Limit("java uncompressed size"));
        }
        let out = decompress_to_vec_zlib_with_limit(r.rest(), size).map_err(|_| Error::Invalid("zlib stream"))?;
        if out.len() != size {
            return Err(Error::Invalid("zlib size mismatch"));
        }
        Ok(out)
    }

    fn send(&mut self, ids: &JavaIds, state: State, name: &str, body: &[u8]) -> Result<()> {
        let id = ids.serverbound_id(state, name)?;
        let mut inner = Writer::new();
        inner.var_u32(id as u32);
        inner.bytes(body);
        let inner = inner.finish();

        let mut framed = Writer::new();
        match self.compression {
            Some(threshold) if inner.len() >= threshold => {
                let z = compress_to_vec_zlib(&inner, 6);
                let mut c = Writer::new();
                c.var_u32(inner.len() as u32);
                c.bytes(&z);
                let c = c.finish();
                framed.var_u32(c.len() as u32);
                framed.bytes(&c);
            }
            Some(_) => {
                framed.var_u32(inner.len() as u32 + 1);
                framed.u8(0);
                framed.bytes(&inner);
            }
            None => {
                framed.var_u32(inner.len() as u32);
                framed.bytes(&inner);
            }
        }
        self.tcp.queue(&framed.finish())
    }

    /// Send a Play-state packet on behalf of the Bedrock player (used by translators).
    pub fn send_play(&mut self, ids: &JavaIds, name: &str, body: &[u8]) -> Result<()> {
        if self.state != State::Play {
            return Err(Error::Protocol("java link is not in the play state".into()));
        }
        self.send(ids, State::Play, name, body)
    }

    // ---------------------------------------------------------------- states

    fn send_hello(&mut self, ids: &JavaIds) -> Result<()> {
        let mut w = Writer::new();
        w.var_u32(self.protocol as u32);
        w.string_var(&self.host);
        w.u16_be(self.port);
        w.var_u32(2); // intent: login
        self.send(ids, State::Handshake, "intention", &w.finish())?;
        self.state = State::Login;

        let mut w = Writer::new();
        w.string_var(&self.profile.name);
        w.bytes(&self.profile.uuid);
        self.send(ids, State::Login, "hello", &w.finish())?;
        self.sent_hello = true;
        Ok(())
    }

    fn send_client_information(&mut self, ids: &JavaIds) -> Result<()> {
        let mut w = Writer::new();
        w.string_var("en_us");
        w.u8(8); // view distance
        w.var_u32(0); // chat mode: enabled
        w.bool(true); // chat colors
        w.u8(0x7f); // all skin parts
        w.var_u32(1); // main hand: right
        w.bool(false); // text filtering
        w.bool(true); // allow server listings
        w.var_u32(0); // particle status: all
        self.send(ids, State::Configuration, "client_information", &w.finish())
    }

    fn answer_query(&mut self, ids: &JavaIds, message_id: u32, channel: &str) -> Result<()> {
        let mut w = Writer::new();
        w.var_u32(message_id);
        if channel == forwarding::CHANNEL {
            w.bool(true);
            w.bytes(&forwarding::build(&self.secret, &self.profile)?);
        } else {
            w.bool(false); // "not understood", like a vanilla client
        }
        self.send(ids, State::Login, "custom_query_answer", &w.finish())
    }

    fn handle(&mut self, ids: &JavaIds, id: i32, body: Vec<u8>, events: &mut Vec<JavaEvent>) -> Result<()> {
        let Some(name) = ids.clientbound_name(self.state, id).map(str::to_owned) else {
            return Ok(()); // unknown or irrelevant packet
        };
        let mut r = Reader::new(&body);
        // Match on a clone so `name` and `body` can be moved into events without a live borrow.
        let key = name.clone();
        match (self.state, key.as_str()) {
            (State::Login, "custom_query") => {
                let message_id = r.var_u32()?;
                let channel = r.string_var(256)?;
                self.answer_query(ids, message_id, &channel)?;
            }
            (State::Login, "login_compression") => {
                let threshold = r.var_u32()? as i32;
                self.compression = usize::try_from(threshold).ok();
            }
            (State::Login, "login_finished") => {
                self.send(ids, State::Login, "login_acknowledged", &[])?;
                self.state = State::Configuration;
                self.send_client_information(ids)?;
            }
            (State::Login, "login_disconnect") | (State::Configuration, "disconnect") => {
                return Err(Error::Protocol("pumpkin refused the login (check proxy.velocity secret)".into()));
            }
            (State::Configuration, "select_known_packs") => {
                let mut w = Writer::new();
                w.var_u32(0); // we know no packs: server sends full registry data
                self.send(ids, State::Configuration, "select_known_packs", &w.finish())?;
            }
            (State::Configuration, "finish_configuration") => {
                self.send(ids, State::Configuration, "finish_configuration", &[])?;
                self.state = State::Play;
            }
            (State::Configuration, "keep_alive") => {
                let payload = r.take(8)?.to_vec();
                self.send(ids, State::Configuration, "keep_alive", &payload)?;
            }
            (State::Configuration, "ping") => {
                let payload = r.take(4)?.to_vec();
                self.send(ids, State::Configuration, "pong", &payload)?;
            }
            (State::Play, "keep_alive") => {
                let payload = r.take(8)?.to_vec();
                self.send(ids, State::Play, "keep_alive", &payload)?;
            }
            (State::Play, "ping") => {
                let payload = r.take(4)?.to_vec();
                self.send(ids, State::Play, "pong", &payload)?;
            }
            (State::Play, "chunk_batch_finished") => {
                self.send(ids, State::Play, "chunk_batch_received", &25.0f32.to_be_bytes())?;
            }
            (State::Play, "player_position") => {
                let teleport_id = r.var_u32()?;
                let mut w = Writer::new();
                w.var_u32(teleport_id);
                self.send(ids, State::Play, "accept_teleportation", &w.finish())?;
                events.push(JavaEvent::Play { name, body });
            }
            (State::Play, _) => events.push(JavaEvent::Play { name, body }),
            _ => {}
        }
        Ok(())
    }
}
