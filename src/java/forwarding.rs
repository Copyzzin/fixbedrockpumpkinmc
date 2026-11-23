//! Velocity "modern forwarding", used here the way Floodgate is used with Geyser: the bridge has
//! already authenticated the Bedrock player (Xbox identity chain), and tells Pumpkin who they are.
//!
//! Pumpkin must run with `[proxy] enabled = true` and `[proxy.velocity] enabled = true, secret = "..."`.
//! The reply to the backend's `velocity:player_info` login query is `HMAC-SHA256(secret, data) || data`
//! where `data` is: version, client address, UUID, username, property count (+ properties).
//! We always answer with forwarding version 1 (the base layout), which newer backends accept.
//!
//! CONSEQUENCE: with forwarding enabled Pumpkin rejects *direct* Java logins. Java players must come
//! through a proxy (e.g. Velocity) or the Java listener must be firewalled to this plugin; see README.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::util::{Error, Result, Writer};

pub const CHANNEL: &str = "velocity:player_info";

pub struct ForwardProfile {
    pub name: String,
    pub uuid: [u8; 16],
    pub ip: String,
}

pub fn build(secret: &[u8], p: &ForwardProfile) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.var_u32(1);
    w.string_var(&p.ip);
    w.bytes(&p.uuid);
    w.string_var(&p.name);
    w.var_u32(0); // no profile properties (no skin textures for Java-side rendering)
    let data = w.finish();

    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| Error::Invalid("forwarding secret"))?;
    mac.update(&data);
    let signature = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(signature.len() + data.len());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&data);
    Ok(out)
}

/// Floodgate-style deterministic UUID for a Bedrock player: `(0, XUID)`.
pub fn uuid_from_xuid(xuid: &str) -> Result<[u8; 16]> {
    let n: u64 = xuid.parse().map_err(|_| Error::Auth("XUID is not numeric".into()))?;
    let mut out = [0u8; 16];
    out[8..].copy_from_slice(&n.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_prefix_and_payload() {
        let p = ForwardProfile { name: ".Steve".into(), uuid: [1; 16], ip: "10.0.0.2".into() };
        let out = build(b"secret", &p).unwrap();
        // 32-byte HMAC, then version(1) + string(len+8) + 16 uuid + string(len+6) + 1 property count
        assert_eq!(out.len(), 32 + 1 + (1 + 8) + 16 + (1 + 6) + 1);
        assert_eq!(out[32], 1);
    }

    #[test]
    fn xuid_maps_to_low_half() {
        let u = uuid_from_xuid("2535428691234567").unwrap();
        assert_eq!(&u[..8], &[0u8; 8]);
        assert_eq!(u64::from_be_bytes(u[8..].try_into().unwrap()), 2535428691234567);
        assert!(uuid_from_xuid("not-a-number").is_err());
    }
}
