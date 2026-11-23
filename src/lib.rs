//! bedrock-bridge: a Geyser-style Bedrock Edition -> Java Edition protocol bridge, packaged as a
//! Pumpkin WASM plugin.
//!
//! ```text
//!  Bedrock client ──UDP/RakNet :19132──► [this plugin: auth + translate] ──TCP loopback──► Pumpkin Java port
//!                                         (Xbox chain check, Velocity-forwarded identity)
//! ```
//!
//! A WASM plugin has no threads and no async runtime, so the whole bridge is a state machine
//! advanced once per server tick by the scheduler (`Bridge::tick`), on non-blocking WASI sockets.
//! Cost of that model: up to one tick (50 ms) of added latency per direction.
//!
//! Pumpkin's built-in Bedrock listener must be disabled (`bedrock_edition = false`) so this plugin can
//! own UDP 19132. See README.md for setup, the security model and the current feature coverage.

mod bedrock;
mod bridge;
mod config;
mod java;
mod net;
mod raknet;
mod util;

use std::cell::{Cell, RefCell};

use pumpkin_plugin_api::permissions as perm;
use pumpkin_plugin_api::scheduler::{self, SchedulerExt};
use pumpkin_plugin_api::{Context, Plugin, PluginMetadata, register_plugin};
use tracing::info;

use crate::bridge::Bridge;

// WASM is single-threaded; thread_local gives the `'static` tick closure access to the bridge
// without requiring the WASI socket handles to be `Send`/`Sync`.
thread_local! {
    static BRIDGE: RefCell<Option<Bridge>> = const { RefCell::new(None) };
    static TASK: Cell<Option<u32>> = const { Cell::new(None) };
}

struct BedrockBridge;

impl Plugin for BedrockBridge {
    fn new() -> Self {
        Self
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "bedrock-bridge".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            authors: vec!["bedrock-bridge contributors".into()],
            description: "Geyser-style Bedrock Edition bridge for Pumpkin".into(),
            dependencies: vec![],
            // Least privilege: no DNS, no HTTP, no env/system info, no loopback-only restriction
            // (the UDP listener must be reachable from outside).
            permissions: vec![
                perm::FS_READ_DATA.into(),
                perm::FS_WRITE_DATA.into(),
                perm::NETWORK_UDP.into(),
                perm::NETWORK_UDP_BIND.into(),
                perm::NETWORK_UDP_OUTGOING_DATAGRAM.into(),
                perm::NETWORK_TCP.into(),
                perm::NETWORK_TCP_CONNECT.into(),
            ],
        }
    }

    fn on_load(&self, context: &Context) -> Result<(), String> {
        let dir = context.get_data_folder();
        let cfg = config::Config::load(&dir).map_err(|e| e.to_string())?;
        let ids = config::load_java_ids(&dir, &cfg).map_err(|e| e.to_string())?;
        let bridge = Bridge::start(cfg, ids).map_err(|e| e.to_string())?;
        BRIDGE.with(|b| *b.borrow_mut() = Some(bridge));

        let task = context.schedule_repeating_task(1, 1, |_server| {
            BRIDGE.with(|cell| {
                if let Ok(mut guard) = cell.try_borrow_mut() {
                    if let Some(bridge) = guard.as_mut() {
                        bridge.tick();
                    }
                }
            });
        });
        TASK.with(|t| t.set(Some(task)));
        info!("bedrock-bridge loaded");
        Ok(())
    }

    fn on_unload(&self, _context: &Context) -> Result<(), String> {
        if let Some(task) = TASK.with(Cell::take) {
            let _ = scheduler::cancel_task(task);
        }
        if let Some(mut bridge) = BRIDGE.with(|b| b.borrow_mut().take()) {
            bridge.shutdown();
        }
        Ok(())
    }
}

register_plugin!(BedrockBridge);
