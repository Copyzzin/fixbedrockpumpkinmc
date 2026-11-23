//! One bridged player: a Bedrock connection upstream, a Java connection downstream.

use std::net::SocketAddrV4;
use std::time::Instant;

use crate::bedrock::batch::BatchCodec;
use crate::bedrock::login::{ClientInfo, Identity};
use crate::bedrock::{self, id};
use crate::java::JavaClient;
use crate::util::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionState {
    AwaitNetworkSettings,
    AwaitLogin,
    /// Waiting for `ClientToServerHandshake` (encryption is now active).
    AwaitHandshake,
    /// Login finished; the version-specific join sequence (resource packs, StartGame, ...) is running.
    Joining,
    /// The Bedrock client has spawned; translators are live.
    InGame,
}

pub struct Session {
    pub addr: SocketAddrV4,
    pub state: SessionState,
    pub created: Instant,
    pub protocol: i32,
    pub identity: Option<Identity>,
    pub client: ClientInfo,
    pub java_name: String,
    pub codec: BatchCodec,
    pub java: Option<JavaClient>,
    /// Packets (`header + body`) waiting to be batched and sent at the end of the tick.
    out: Vec<Vec<u8>>,
    out_bytes: usize,
    max_out_bytes: usize,
    /// Set once the session must be torn down after its pending packets are flushed.
    pub close_reason: Option<String>,
}

impl Session {
    pub fn new(addr: SocketAddrV4, now: Instant, max_batch_bytes: usize, max_out_bytes: usize) -> Self {
        Self {
            addr,
            state: SessionState::AwaitNetworkSettings,
            created: now,
            protocol: 0,
            identity: None,
            client: ClientInfo::default(),
            java_name: String::new(),
            codec: BatchCodec::new(max_batch_bytes),
            java: None,
            out: Vec::new(),
            out_bytes: 0,
            max_out_bytes,
            close_reason: None,
        }
    }

    /// Queue a Bedrock packet. Fails (and marks the session for closing) if the client is not keeping up.
    pub fn queue(&mut self, packet_id: u32, body: &[u8]) -> Result<()> {
        if self.out_bytes + body.len() > self.max_out_bytes {
            self.close_reason = Some("client too slow".into());
            return Err(Error::Limit("bedrock send queue"));
        }
        self.out_bytes += body.len() + 5;
        self.out.push(bedrock::packet(packet_id, body));
        Ok(())
    }

    pub fn take_pending(&mut self) -> Vec<Vec<u8>> {
        self.out_bytes = 0;
        std::mem::take(&mut self.out)
    }

    pub fn has_pending(&self) -> bool {
        !self.out.is_empty()
    }

    /// Show `message` on the disconnect screen and close once flushed. First reason wins.
    pub fn kick(&mut self, message: &str) {
        if self.close_reason.is_some() {
            return;
        }
        self.out.push(bedrock::packet(id::DISCONNECT, &bedrock::disconnect_body(message)));
        self.close_reason = Some(message.to_owned());
    }
}
