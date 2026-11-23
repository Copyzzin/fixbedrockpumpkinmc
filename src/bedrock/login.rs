//! Bedrock `Login` packet: parsing and identity-chain verification.
//!
//! SECURITY: skipping or weakening verification lets anyone impersonate any player (Geyser shipped
//! exactly that bug in 2021, CVE-2021-39177). In `online` mode this module therefore requires that
//! (1) every JWT in the chain verifies against the key named in its own `x5u` header, (2) each token
//! is signed by the key certified by the previous one, (3) some token is signed by a configured
//! Mojang root key, and (4) the client-data JWT verifies against the key from the last chain token.
//! Anything else is rejected. Root keys are configuration, not hard-coded: see README.
//!
//! Supported login formats: the classic certificate chain (`{"chain":[...]}`, optionally wrapped in
//! `{"Certificate":"{...}"}`). The newer token-based format (`"Token"`) is detected and rejected with
//! a clear error until an OpenID verifier is added.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use serde_json::Value;

use crate::util::{Error, Reader, Result};

const MAX_LOGIN_BYTES: usize = 1024 * 1024;
const CLOCK_SKEW_SECS: f64 = 60.0;

#[derive(Debug, Clone)]
pub struct Identity {
    pub xuid: String,
    pub display_name: String,
    pub client_key: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    pub language: String,
    pub device_os: i64,
    pub game_version: String,
}

pub struct LoginData {
    pub protocol: i32,
    pub identity: Identity,
    pub client: ClientInfo,
}

pub struct ChainVerifier {
    online: bool,
    roots: Vec<String>,
}

struct Jwt<'a> {
    signing_input: &'a str,
    header: Value,
    claims: Value,
    signature: Vec<u8>,
}

fn b64url(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| Error::Invalid("base64url"))
}

fn split_jwt(token: &str) -> Result<Jwt<'_>> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Invalid("jwt structure"));
    };
    let json = |seg: &str| -> Result<Value> {
        serde_json::from_slice(&b64url(seg)?).map_err(|_| Error::Invalid("jwt json"))
    };
    Ok(Jwt {
        signing_input: &token[..h.len() + 1 + p.len()],
        header: json(h)?,
        claims: json(p)?,
        signature: b64url(s)?,
    })
}

fn decode_key(b64: &str) -> Result<VerifyingKey> {
    let der = STANDARD.decode(b64.trim()).map_err(|_| Error::Invalid("key base64"))?;
    VerifyingKey::from_public_key_der(&der).map_err(|_| Error::Invalid("key der"))
}

fn verify_signature(key_b64: &str, jwt: &Jwt<'_>) -> Result<()> {
    let key = decode_key(key_b64)?;
    let sig = Signature::try_from(jwt.signature.as_slice())
        .map_err(|_| Error::Auth("bad signature encoding".into()))?;
    key.verify(jwt.signing_input.as_bytes(), &sig)
        .map_err(|_| Error::Auth("signature mismatch".into()))
}

fn check_time(claims: &Value, now: u64) -> Result<()> {
    let now = now as f64;
    if let Some(exp) = claims.get("exp").and_then(Value::as_f64) {
        if now > exp + CLOCK_SKEW_SECS {
            return Err(Error::Auth("token expired".into()));
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_f64) {
        if now + CLOCK_SKEW_SECS < nbf {
            return Err(Error::Auth("token not yet valid".into()));
        }
    }
    Ok(())
}

fn extract_chain(raw: &[u8]) -> Result<Vec<String>> {
    let outer: Value = serde_json::from_slice(raw).map_err(|_| Error::Invalid("login json"))?;
    let chain_value = if let Some(cert) = outer.get("Certificate").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let inner: Value = serde_json::from_str(cert).map_err(|_| Error::Invalid("certificate json"))?;
        inner.get("chain").cloned()
    } else if outer.get("chain").is_some() {
        outer.get("chain").cloned()
    } else if outer.get("Token").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
        return Err(Error::Auth("token-based Bedrock login is not supported yet".into()));
    } else {
        None
    };
    let list = chain_value
        .and_then(|v| v.as_array().cloned())
        .ok_or(Error::Invalid("missing certificate chain"))?;
    list.into_iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Invalid("chain entry")))
        .collect()
}

impl ChainVerifier {
    pub fn new(online: bool, root_keys: &[String]) -> Result<Self> {
        let mut roots = Vec::new();
        for k in root_keys {
            let k = k.trim();
            decode_key(k).map_err(|_| Error::Auth("auth.mojang_root_public_keys contains an invalid key".into()))?;
            roots.push(k.to_owned());
        }
        if online && roots.is_empty() {
            return Err(Error::Auth(
                "auth.mode = \"online\" requires at least one key in auth.mojang_root_public_keys".into(),
            ));
        }
        Ok(Self { online, roots })
    }

    /// Walk the chain; returns the last token's claims and whether a configured root vouched for it.
    fn walk_chain(&self, chain: &[String], now: u64) -> Result<(Value, bool)> {
        if chain.is_empty() || chain.len() > 4 {
            return Err(Error::Invalid("chain length"));
        }
        let mut expected: Option<String> = None;
        let mut trusted = false;
        let mut last = Value::Null;
        for token in chain {
            let jwt = split_jwt(token)?;
            if jwt.header.get("alg").and_then(Value::as_str) != Some("ES384") {
                return Err(Error::Auth("unsupported jwt algorithm".into()));
            }
            let x5u = jwt
                .header
                .get("x5u")
                .and_then(Value::as_str)
                .ok_or(Error::Invalid("jwt x5u"))?
                .to_owned();
            if let Some(e) = &expected {
                if *e != x5u {
                    return Err(Error::Auth("certificate chain is not contiguous".into()));
                }
            }
            if self.online {
                verify_signature(&x5u, &jwt)?;
                check_time(&jwt.claims, now)?;
                if self.roots.iter().any(|r| *r == x5u) {
                    trusted = true;
                }
            }
            expected = jwt.claims.get("identityPublicKey").and_then(Value::as_str).map(str::to_owned);
            last = jwt.claims;
        }
        Ok((last, trusted))
    }

    pub fn parse(&self, body: &[u8], now_unix: u64) -> Result<LoginData> {
        let mut r = Reader::new(body);
        let protocol = r.i32_be()?;
        let len = r.var_u32()? as usize;
        if len > MAX_LOGIN_BYTES {
            return Err(Error::Limit("login payload"));
        }
        let mut b = Reader::new(r.take(len)?);
        let chain_len = usize::try_from(b.i32_le()?).map_err(|_| Error::Invalid("chain length"))?;
        let chain_json = b.take(chain_len)?;
        let jwt_len = usize::try_from(b.i32_le()?).map_err(|_| Error::Invalid("client jwt length"))?;
        let client_jwt = std::str::from_utf8(b.take(jwt_len)?).map_err(|_| Error::Invalid("client jwt utf-8"))?;

        let chain = extract_chain(chain_json)?;
        let (claims, trusted) = self.walk_chain(&chain, now_unix)?;
        if self.online && !trusted {
            return Err(Error::Auth("identity is not signed by a trusted root (not logged in to Xbox Live?)".into()));
        }

        let client_key = claims
            .get("identityPublicKey")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid("identityPublicKey"))?
            .to_owned();
        let extra = claims.get("extraData").ok_or(Error::Auth("missing extraData".into()))?;
        let display_name = extra.get("displayName").and_then(Value::as_str).unwrap_or_default().to_owned();
        let xuid = extra.get("XUID").and_then(Value::as_str).unwrap_or_default().to_owned();
        if display_name.is_empty() || display_name.len() > 64 {
            return Err(Error::Invalid("display name"));
        }

        // The client-data JWT must be signed by the key the chain certified.
        let data_jwt = split_jwt(client_jwt)?;
        if self.online {
            verify_signature(&client_key, &data_jwt)?;
        }
        let c = &data_jwt.claims;
        let client = ClientInfo {
            language: c.get("LanguageCode").and_then(Value::as_str).unwrap_or("en_US").chars().take(16).collect(),
            device_os: c.get("DeviceOS").and_then(Value::as_i64).unwrap_or(0),
            game_version: c.get("GameVersion").and_then(Value::as_str).unwrap_or_default().chars().take(32).collect(),
        };

        Ok(LoginData {
            protocol,
            identity: Identity { xuid, display_name, client_key, verified: self.online },
            client,
        })
    }
}
