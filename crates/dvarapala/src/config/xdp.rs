//! The `[xdp]` section (RFC 0011).

use std::time::Duration;

use dvarapala_xdp::{Attach, XdpConfig};
use serde::Deserialize;

use super::{Mode, duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachMode {
    Auto,
    Native,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Xdp {
    /// Unset turns XDP off.
    pub interface: Option<String>,
    pub mode: Mode,
    pub attach: AttachMode,
    pub allow: Vec<String>,
    pub block: Vec<String>,
    #[serde(deserialize_with = "duration")]
    pub block_ttl: Duration,
    pub max_blocks: u32,
    pub pps: u32,
    pub syn_pps: u32,
    pub udp_pps: u32,
    pub burst: u32,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub max_sources: u32,
}

impl Default for Xdp {
    fn default() -> Self {
        Self {
            interface: None,
            mode: Mode::Observe,
            attach: AttachMode::Auto,
            allow: Vec::new(),
            block: Vec::new(),
            block_ttl: Duration::from_secs(600),
            max_blocks: 65_536,
            pps: 0,
            syn_pps: 100,
            udp_pps: 0,
            burst: 200,
            prefix_v4: 32,
            prefix_v6: 64,
            max_sources: 1_048_576,
        }
    }
}

/// What the loader needs: the interface, how to attach, the program's
/// settings.
#[derive(Debug, Clone, PartialEq)]
pub struct XdpPlan {
    pub interface: String,
    pub attach: Attach,
    pub config: XdpConfig,
}

impl Xdp {
    /// `None` when `xdp.interface` is unset. `tcp_port` is the listener's,
    /// `udp_port` the QUIC listener's (0 without one).
    #[allow(dead_code)]
    pub fn plan(&self, tcp_port: u16, udp_port: u16) -> Result<Option<XdpPlan>, String> {
        let _ = (tcp_port, udp_port);
        todo!("rfc 0011")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "rfc 0011"]
    fn off_without_an_interface() {
        assert_eq!(Xdp::default().plan(8080, 0), Ok(None));
    }

    // RFC 0011 case 10
    #[test]
    #[ignore = "rfc 0011"]
    fn missing_interface_names_the_key() {
        let x = Xdp {
            interface: Some("dvx-none0".into()),
            ..Xdp::default()
        };
        let e = x.plan(8080, 0).unwrap_err();
        assert!(e.contains("xdp.interface"), "{e}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "rfc 0011"]
    fn plan_carries_the_ports_and_lists() {
        let x = Xdp {
            interface: Some("lo".into()),
            mode: Mode::Enforce,
            allow: vec!["192.0.2.0/24".into()],
            block: vec!["2001:db8::/32".into()],
            ..Xdp::default()
        };
        let p = x.plan(8080, 8443).unwrap().unwrap();
        assert_eq!((p.config.tcp_port, p.config.udp_port), (8080, 8443));
        assert!(p.config.enforce);
        assert_eq!((p.config.allow.len(), p.config.block.len()), (1, 1));
        let bad = Xdp {
            block: vec!["192.0.2.0/33".into()],
            ..x
        };
        assert!(bad.plan(8080, 0).unwrap_err().contains("xdp.block"));
    }
}
