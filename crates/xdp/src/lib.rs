//! Loads the RFC 0011 XDP program, attaches it and keeps its maps: the
//! allow and block tries and the counters. The program itself is in
//! `crates/xdp-ebpf`; the parser and map layouts in `crates/xdp-common`.

mod config;
#[cfg(all(feature = "load", target_os = "linux"))]
mod loader;
mod maps;

pub use config::{Attach, XdpConfig, XdpError};
#[cfg(all(feature = "load", target_os = "linux"))]
pub use loader::Xdp;
pub use maps::{Add, Blocks, key};
