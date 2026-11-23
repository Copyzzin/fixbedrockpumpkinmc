//! The version-specific part of a Bedrock join.
//!
//! After login succeeds a Bedrock client expects a precise, *per-release* packet exchange: resource
//! pack info/stack, `StartGame` (dozens of fields that change almost every release), item registry,
//! biome and actor definitions, creative content, chunk radius, the first chunks, and finally
//! `PlayStatus(PlayerSpawn)`. Geyser gets this from per-version codecs of the CloudburstMC protocol
//! library; there is no equivalent shortcut here.
//!
//! This trait is the seam. Implement it once per supported Bedrock protocol number, generating field
//! layouts from Mojang's published protocol documentation, and register the implementation in
//! `Bridge::start`. Until then `NotImplemented` ends the session with an explicit message, so the
//! plugin fails visibly instead of leaving players stuck on a loading screen.

use super::session::Session;
use crate::util::{Reader, Result};

pub trait JoinSequence {
    /// Called right after `PlayStatus(LoginSuccess)` was queued. Send resource pack info etc. here.
    fn begin(&self, session: &mut Session) -> Result<()>;

    /// Handle one client packet while `state == Joining` (resource pack responses, chunk radius request,
    /// `SetLocalPlayerAsInitialized`, ...). Set `session.state = SessionState::InGame` when the client
    /// has spawned. Return `Ok(())` for packets that need no action.
    fn on_packet(&self, session: &mut Session, packet_id: u32, r: &mut Reader) -> Result<()>;
}

pub struct NotImplemented {
    pub protocol: i32,
}

impl JoinSequence for NotImplemented {
    fn begin(&self, session: &mut Session) -> Result<()> {
        session.kick(&format!(
            "bedrock-bridge: the join sequence for Bedrock protocol {} is not implemented in this build",
            self.protocol
        ));
        Ok(())
    }

    fn on_packet(&self, _session: &mut Session, _packet_id: u32, _r: &mut Reader) -> Result<()> {
        Ok(())
    }
}
