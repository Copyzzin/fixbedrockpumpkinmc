//! Packet translators, in the spirit of Geyser's `PacketTranslatorRegistry`: one small handler per
//! packet, registered by Bedrock packet id (upstream) or Java packet name (downstream).
//!
//! Implemented: chat and commands (both directions) and server-initiated disconnects.
//! NOT implemented yet (each is its own translator): movement/`PlayerAuthInput`, chunks and block
//! updates (needs Java<->Bedrock block-state mappings), inventory/items, entities and metadata,
//! effects, scoreboard/boss bars, forms. See README "Roadmap".

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::session::Session;
use crate::bedrock::{self, id};
use crate::java::JavaIds;
use crate::java::nbt::read_component_text;
use crate::util::{Error, Reader, Result, Writer};

/// Everything a translator may touch.
pub struct Ctx<'a> {
    pub session: &'a mut Session,
    pub ids: &'a JavaIds,
}

/// Bedrock (client) -> Java (server).
pub trait BedrockToJava {
    fn packet_id(&self) -> u32;
    fn run(&self, ctx: &mut Ctx, r: &mut Reader) -> Result<()>;
}

/// Java (server) -> Bedrock (client).
pub trait JavaToBedrock {
    fn packet_name(&self) -> &'static str;
    fn run(&self, ctx: &mut Ctx, r: &mut Reader) -> Result<()>;
}

#[derive(Default)]
pub struct Registry {
    upstream: HashMap<u32, Box<dyn BedrockToJava>>,
    downstream: HashMap<&'static str, Box<dyn JavaToBedrock>>,
}

impl Registry {
    pub fn with_defaults() -> Self {
        let mut r = Self::default();
        r.upstream(ChatToJava);
        r.upstream(CommandToJava);
        r.downstream(SystemChatToBedrock);
        r.downstream(DisconnectToBedrock);
        r
    }

    pub fn upstream<T: BedrockToJava + 'static>(&mut self, t: T) {
        self.upstream.insert(t.packet_id(), Box::new(t));
    }

    pub fn downstream<T: JavaToBedrock + 'static>(&mut self, t: T) {
        self.downstream.insert(t.packet_name(), Box::new(t));
    }

    pub fn bedrock(&self, packet_id: u32) -> Option<&dyn BedrockToJava> {
        self.upstream.get(&packet_id).map(Box::as_ref)
    }

    pub fn java(&self, name: &str) -> Option<&dyn JavaToBedrock> {
        self.downstream.get(name).map(Box::as_ref)
    }
}

fn java_link<'a>(ctx: &'a mut Ctx) -> Result<&'a mut crate::java::JavaClient> {
    ctx.session.java.as_mut().ok_or_else(|| Error::Protocol("no java link".into()))
}

/// Drop control characters and cap to the Java limit so Bedrock input can't smuggle formatting or overflow.
fn sanitize_chat(s: &str, max_chars: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max_chars).collect()
}

// ------------------------------------------------------------------ Bedrock -> Java

struct ChatToJava;

impl BedrockToJava for ChatToJava {
    fn packet_id(&self) -> u32 {
        id::TEXT
    }

    fn run(&self, ctx: &mut Ctx, r: &mut Reader) -> Result<()> {
        let kind = r.u8()?;
        let _needs_translation = r.u8()?;
        if kind != 1 {
            return Ok(()); // only player chat is accepted from clients
        }
        let _source_name = r.string_var(64)?;
        let message = sanitize_chat(&r.string_var(1024)?, 256);
        if message.is_empty() {
            return Ok(());
        }
        let ids = ctx.ids;
        let link = java_link(ctx)?;
        if let Some(cmd) = message.strip_prefix('/') {
            let mut w = Writer::new();
            w.string_var(cmd);
            return link.send_play(ids, "chat_command", &w.finish());
        }
        // Unsigned chat message: text, timestamp, salt, no signature, ack offset, ack bitset (20 bits), checksum.
        // VERSION-SENSITIVE (1.21.5+ layout).
        let millis = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        let mut w = Writer::new();
        w.string_var(&message);
        w.i64_be(millis);
        w.i64_be(0);
        w.bool(false);
        w.var_u32(0);
        w.bytes(&[0, 0, 0]);
        w.u8(0);
        link.send_play(ids, "chat", &w.finish())
    }
}

struct CommandToJava;

impl BedrockToJava for CommandToJava {
    fn packet_id(&self) -> u32 {
        id::COMMAND_REQUEST
    }

    fn run(&self, ctx: &mut Ctx, r: &mut Reader) -> Result<()> {
        let line = sanitize_chat(&r.string_var(1024)?, 256);
        let cmd = line.strip_prefix('/').unwrap_or(&line);
        if cmd.is_empty() {
            return Ok(());
        }
        let mut w = Writer::new();
        w.string_var(cmd);
        let ids = ctx.ids;
        java_link(ctx)?.send_play(ids, "chat_command", &w.finish())
    }
}

// ------------------------------------------------------------------ Java -> Bedrock

struct SystemChatToBedrock;

impl JavaToBedrock for SystemChatToBedrock {
    fn packet_name(&self) -> &'static str {
        "system_chat"
    }

    fn run(&self, ctx: &mut Ctx, r: &mut Reader) -> Result<()> {
        let text = read_component_text(r)?;
        let overlay = r.u8().map(|b| b != 0).unwrap_or(false);
        let kind = if overlay { 5 } else { 0 }; // tip (action bar) or raw
        ctx.session.queue(id::TEXT, &bedrock::text_body(kind, &text))
    }
}

struct DisconnectToBedrock;

impl JavaToBedrock for DisconnectToBedrock {
    fn packet_name(&self) -> &'static str {
        "disconnect"
    }

    fn run(&self, ctx: &mut Ctx, r: &mut Reader) -> Result<()> {
        let reason = read_component_text(r).unwrap_or_default();
        let reason = if reason.is_empty() { "Disconnected".to_owned() } else { reason };
        ctx.session.kick(&reason);
        Ok(())
    }
}
