//! Java packet-id table, loaded at runtime from the vanilla data generator's `packets.json`
//! (`java -DbundlerMainClass=net.minecraft.data.Main -jar server.jar --reports`).
//!
//! Ids change every Minecraft release. Resolving them by *name* from a file that belongs to the exact
//! server version avoids hard-coding numbers that silently go stale, and `validate()` fails loudly at
//! startup if a packet this bridge needs is missing or was renamed.

use std::collections::HashMap;

use serde_json::Value;

use crate::util::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum State {
    Handshake,
    Status,
    Login,
    Configuration,
    Play,
}

impl State {
    const ALL: [(State, &'static str); 5] = [
        (State::Handshake, "handshake"),
        (State::Status, "status"),
        (State::Login, "login"),
        (State::Configuration, "configuration"),
        (State::Play, "play"),
    ];
}

/// Packets the bridge cannot work without: (state, name).
const REQUIRED_SERVERBOUND: &[(State, &str)] = &[
    (State::Handshake, "intention"),
    (State::Login, "hello"),
    (State::Login, "custom_query_answer"),
    (State::Login, "login_acknowledged"),
    (State::Configuration, "client_information"),
    (State::Configuration, "finish_configuration"),
    (State::Configuration, "select_known_packs"),
    (State::Configuration, "keep_alive"),
    (State::Configuration, "pong"),
    (State::Play, "keep_alive"),
    (State::Play, "pong"),
    (State::Play, "accept_teleportation"),
    (State::Play, "chunk_batch_received"),
    (State::Play, "chat"),
    (State::Play, "chat_command"),
];

const REQUIRED_CLIENTBOUND: &[(State, &str)] = &[
    (State::Login, "custom_query"),
    (State::Login, "login_compression"),
    (State::Login, "login_finished"),
    (State::Login, "login_disconnect"),
    (State::Configuration, "finish_configuration"),
    (State::Configuration, "select_known_packs"),
    (State::Configuration, "keep_alive"),
    (State::Configuration, "ping"),
    (State::Configuration, "disconnect"),
    (State::Play, "keep_alive"),
    (State::Play, "ping"),
    (State::Play, "disconnect"),
    (State::Play, "chunk_batch_finished"),
    (State::Play, "player_position"),
    (State::Play, "system_chat"),
];

pub struct JavaIds {
    clientbound: HashMap<(State, i32), String>,
    serverbound: HashMap<(State, String), i32>,
}

impl JavaIds {
    pub fn parse(json: &str) -> Result<Self> {
        let root: Value =
            serde_json::from_str(json).map_err(|e| Error::Protocol(format!("java packets json: {e}")))?;
        let mut ids = Self { clientbound: HashMap::new(), serverbound: HashMap::new() };
        for (state, key) in State::ALL {
            let Some(section) = root.get(key) else {
                continue;
            };
            for (direction, clientbound) in [("clientbound", true), ("serverbound", false)] {
                let Some(map) = section.get(direction).and_then(Value::as_object) else {
                    continue;
                };
                for (full_name, entry) in map {
                    let Some(id) = entry.get("protocol_id").and_then(Value::as_i64) else {
                        continue;
                    };
                    let id = i32::try_from(id).map_err(|_| Error::Invalid("packet id out of range"))?;
                    let name = full_name.strip_prefix("minecraft:").unwrap_or(full_name).to_owned();
                    if clientbound {
                        ids.clientbound.insert((state, id), name);
                    } else {
                        ids.serverbound.insert((state, name), id);
                    }
                }
            }
        }
        ids.validate()?;
        Ok(ids)
    }

    fn validate(&self) -> Result<()> {
        let mut missing = Vec::new();
        for &(state, name) in REQUIRED_SERVERBOUND {
            if !self.serverbound.contains_key(&(state, name.to_owned())) {
                missing.push(format!("serverbound {state:?}/{name}"));
            }
        }
        for &(state, name) in REQUIRED_CLIENTBOUND {
            if !self.clientbound.values().any(|n| n == name)
                || !self.clientbound.iter().any(|((s, _), n)| *s == state && n == name)
            {
                missing.push(format!("clientbound {state:?}/{name}"));
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "packets.json is missing packets this bridge needs (renamed in this version?): {}",
                missing.join(", ")
            )))
        }
    }

    pub fn clientbound_name(&self, state: State, id: i32) -> Option<&str> {
        self.clientbound.get(&(state, id)).map(String::as_str)
    }

    pub fn serverbound_id(&self, state: State, name: &str) -> Result<i32> {
        self.serverbound
            .get(&(state, name.to_owned()))
            .copied()
            .ok_or_else(|| Error::Protocol(format!("unknown serverbound packet {state:?}/{name}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_required_packets_are_reported() {
        let json = r#"{"handshake":{"serverbound":{"minecraft:intention":{"protocol_id":0}}}}"#;
        let err = JavaIds::parse(json).err().expect("must fail");
        assert!(err.to_string().contains("login"));
    }
}
