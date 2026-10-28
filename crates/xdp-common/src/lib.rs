//! Shared by the XDP program (`crates/xdp-ebpf`, `no_std`, BPF target)
//! and its loader (`crates/xdp`): the packet parser and the layout of
//! every map (RFC 0011).

#![no_std]

mod parse;
mod shared;

pub use parse::{Bytes, Packet, Proto, parse};
pub use shared::{ACTIONS, Action, COUNTERS, Config, REASONS, Rate, Reason, counter};
