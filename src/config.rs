//! Plugin configuration (`plugins/data/bedrock-bridge/config.toml`).
//!
//! Defaults are deliberately *not* usable for the version-specific fields (`protocol`, `forwarding_secret`,
//! root keys): the plugin refuses to start until they are filled in, instead of guessing.

use serde::{Deserialize, Serialize};

use crate::java::JavaIds;
use crate::util::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Verify the Xbox Live identity chain. Required for any public server.
    Online,
    /// Trust the client's claimed identity. Anyone can impersonate anyone. LAN/testing only.
    Offline,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BedrockConfig {
    pub bind_address: String,
    pub motd: String,
    pub sub_motd: String,
    pub max_players: u32,
    /// Bedrock protocol number the join sequence was written for (REQUIRED).
    pub protocol: i32,
    /// Human-readable Bedrock version, shown in the server list.
    pub game_version: String,
    pub max_mtu: u16,
    pub compression_threshold: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct JavaConfig {
    /// Pumpkin's Java listener, as `ip:port` (IPv4 literal; hostnames are not resolved).
    pub address: String,
    /// Java protocol number of the Pumpkin build (`protocol_version` in the server's version.json) (REQUIRED).
    pub protocol_version: i32,
    /// `packets.json` from the matching vanilla data generator run, relative to the plugin data folder.
    pub packets_json: String,
    /// Must equal `[proxy.velocity] secret` in Pumpkin's config (REQUIRED).
    pub forwarding_secret: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    pub mode: AuthMode,
    /// Base64 (DER/SPKI) public keys accepted as the Mojang/Xbox root of the login chain.
    pub mojang_root_public_keys: Vec<String>,
    /// Encrypt the Bedrock connection (strongly recommended; required to bind a session to the verified key).
    pub encryption: bool,
    /// Prefix for Java usernames of Bedrock players, to avoid clashes with Java accounts.
    pub username_prefix: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_sessions: usize,
    pub max_sessions_per_ip: usize,
    pub max_batch_bytes: usize,
    pub max_queued_bytes_per_session: usize,
    pub login_timeout_secs: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub bedrock: BedrockConfig,
    pub java: JavaConfig,
    pub auth: AuthConfig,
    pub limits: LimitsConfig,
}

impl Default for BedrockConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:19132".into(),
            motd: "Pumpkin".into(),
            sub_motd: "bedrock-bridge".into(),
            max_players: 100,
            protocol: 0,
            game_version: String::new(),
            max_mtu: 1400,
            compression_threshold: 256,
        }
    }
}

impl Default for JavaConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:25565".into(),
            protocol_version: 0,
            packets_json: "java_packets.json".into(),
            forwarding_secret: String::new(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Online,
            mojang_root_public_keys: Vec::new(),
            encryption: true,
            username_prefix: ".".into(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            max_sessions_per_ip: 4,
            max_batch_bytes: 4 * 1024 * 1024,
            max_queued_bytes_per_session: 8 * 1024 * 1024,
            login_timeout_secs: 30,
        }
    }
}

impl Config {
    /// Load `config.toml` from the plugin data folder, writing a template on first run.
    pub fn load(dir: &str) -> Result<Self> {
        let path = format!("{dir}/config.toml");
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|e| Error::Protocol(format!("{path}: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Config::default();
                let text = toml::to_string_pretty(&cfg).map_err(|e| Error::Protocol(e.to_string()))?;
                std::fs::write(&path, text).map_err(|e| Error::Io(e.to_string()))?;
                Ok(cfg)
            }
            Err(e) => Err(Error::Io(format!("{path}: {e}"))),
        }
    }

    /// Fail closed: refuse to run with unset or unsafe values.
    pub fn validate(&self) -> Result<()> {
        let mut problems: Vec<&str> = Vec::new();
        if self.bedrock.protocol <= 0 {
            problems.push("bedrock.protocol must be set");
        }
        if self.java.protocol_version <= 0 {
            problems.push("java.protocol_version must be set");
        }
        if self.java.forwarding_secret.is_empty() {
            problems.push("java.forwarding_secret must match Pumpkin's [proxy.velocity] secret");
        }
        if self.auth.mode == AuthMode::Online && self.auth.mojang_root_public_keys.is_empty() {
            problems.push("auth.mojang_root_public_keys is empty (required in online mode)");
        }
        if self.auth.mode == AuthMode::Online && !self.auth.encryption {
            problems.push("auth.encryption must be true in online mode");
        }
        if self.auth.username_prefix.len() > 4 {
            problems.push("auth.username_prefix is too long (Java names are limited to 16 characters)");
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol(format!("invalid config: {}", problems.join("; "))))
        }
    }
}

pub fn load_java_ids(dir: &str, cfg: &Config) -> Result<JavaIds> {
    let path = format!("{dir}/{}", cfg.java.packets_json);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        Error::Io(format!("{path}: {e} (generate it with the vanilla data generator, see README)"))
    })?;
    JavaIds::parse(&text)
}
