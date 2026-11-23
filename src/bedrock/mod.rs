//! Bedrock Edition protocol layer (above RakNet).
//!
//! * `batch`  – 0xFE batch framing, compression, optional encryption
//! * `crypto` – ECDH (P-384) key exchange + AES-256-CTR packet encryption
//! * `login`  – Login packet parsing and identity-chain verification
//!
//! Packet ids below are the stable low ids used by the connection handshake.
//! Layouts of *version-specific* packets (StartGame, ResourcePacks*, ...) are intentionally
//! NOT here: they change between releases and belong in a per-version `JoinSequence`
//! (see `bridge/join.rs`).

pub mod batch;
pub mod crypto;
pub mod login;

use crate::util::Writer;

pub mod id {
    pub const LOGIN: u32 = 1;
    pub const PLAY_STATUS: u32 = 2;
    pub const SERVER_TO_CLIENT_HANDSHAKE: u32 = 3;
    pub const CLIENT_TO_SERVER_HANDSHAKE: u32 = 4;
    pub const DISCONNECT: u32 = 5;
    pub const TEXT: u32 = 9;
    pub const COMMAND_REQUEST: u32 = 77;
    pub const NETWORK_SETTINGS: u32 = 143;
    pub const REQUEST_NETWORK_SETTINGS: u32 = 193;
}

pub mod play_status {
    pub const LOGIN_SUCCESS: i32 = 0;
    pub const FAILED_CLIENT_OLD: i32 = 1;
    pub const FAILED_SERVER_OLD: i32 = 2;
}

/// Bedrock packet header: id in the low 10 bits, sub-client ids above (always 0 here).
pub fn packet(id: u32, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.var_u32(id);
    w.bytes(body);
    w.finish()
}

pub fn play_status_body(status: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.i32_be(status);
    w.finish()
}

/// `NetworkSettings`: compression threshold, algorithm 0 = zlib (raw deflate), no client throttle.
pub fn network_settings_body(threshold: u16) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16_le(threshold);
    w.u16_le(0);
    w.bool(false);
    w.u8(0);
    w.f32_le(0.0);
    w.finish()
}

pub fn server_to_client_handshake_body(jwt: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.string_var(jwt);
    w.finish()
}

/// `Disconnect` body for the 1.21.x layout: reason enum, hide-screen flag, message, filtered message.
/// VERSION-SENSITIVE: re-check against the protocol docs of the target Bedrock release.
pub fn disconnect_body(message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.var_u32(0); // DisconnectFailReason::Unknown
    w.bool(false);
    w.string_var(message);
    w.string_var(message);
    w.finish()
}

/// `Text` body (server -> client). `kind`: 0 = raw, 5 = tip (action bar).
/// Layout for 1.21.x: kind, needs-translation, message, xuid, platform chat id, optional filtered message.
/// VERSION-SENSITIVE: re-check against the protocol docs of the target Bedrock release.
pub fn text_body(kind: u8, message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(kind);
    w.bool(false);
    w.string_var(message);
    w.string_var("");
    w.string_var("");
    w.bool(false);
    w.finish()
}
