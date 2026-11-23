//! Java Edition side: the bridge speaks the Java protocol *as a client* to Pumpkin's loopback port.

pub mod client;
pub mod forwarding;
pub mod ids;
pub mod nbt;

pub use client::{JavaClient, JavaEvent};
pub use ids::JavaIds;
