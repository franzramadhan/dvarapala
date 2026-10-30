//! The `[xdp]` section (RFC 0011).

use std::path::Path;
use std::time::Duration;

use dvarapala_engine::Cidr;
use dvarapala_xdp::{Attach, XdpConfig};
use serde::{Deserialize, Serialize};

use super::{Mode, duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachMode {
    Auto,
    Native,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Xdp {
    /// Unset turns XDP off.
    pub interface: Option<String>,
    pub mode: Mode,
    pub attach: AttachMode,
    pub allow: Vec<String>,
    pub block: Vec<String>,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
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
    pub fn plan(&self, tcp_port: u16, udp_port: u16) -> Result<Option<XdpPlan>, String> {
        let Some(interface) = &self.interface else {
            return Ok(None);
        };
        if interface.is_empty() || !Path::new("/sys/class/net").join(interface).exists() {
            return Err(format!("xdp.interface {interface:?}: no such interface"));
        }
        let cidrs = |key: &str, list: &[String]| {
            list.iter()
                .map(|c| c.parse::<Cidr>().map_err(|e| format!("xdp.{key}: {e}")))
                .collect::<Result<Vec<_>, _>>()
        };
        let allow = cidrs("allow", &self.allow)?;
        let block = cidrs("block", &self.block)?;
        if self.burst == 0 && (self.pps > 0 || self.syn_pps > 0 || self.udp_pps > 0) {
            return Err("xdp.burst must be at least 1".into());
        }
        if self.prefix_v4 > 32 || self.prefix_v6 > 128 {
            return Err("xdp.prefix_v4 is at most 32, xdp.prefix_v6 at most 128".into());
        }
        if self.max_sources == 0 {
            return Err("xdp.max_sources must be at least 1".into());
        }
        if block.len() > self.max_blocks as usize {
            return Err(format!(
                "xdp.block has {} entries, over xdp.max_blocks ({})",
                block.len(),
                self.max_blocks
            ));
        }
        Ok(Some(XdpPlan {
            interface: interface.clone(),
            attach: match self.attach {
                AttachMode::Auto => Attach::Auto,
                AttachMode::Native => Attach::Native,
                AttachMode::Generic => Attach::Generic,
            },
            config: XdpConfig {
                enforce: self.mode == Mode::Enforce,
                allow,
                block,
                block_ttl: self.block_ttl,
                max_blocks: self.max_blocks,
                pps: self.pps,
                syn_pps: self.syn_pps,
                udp_pps: self.udp_pps,
                burst: self.burst,
                prefix_v4: self.prefix_v4,
                prefix_v6: self.prefix_v6,
                max_sources: self.max_sources,
                tcp_port,
                udp_port,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_without_an_interface() {
        assert_eq!(Xdp::default().plan(8080, 0), Ok(None));
    }

    // RFC 0011 case 10
    #[test]
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

    #[cfg(target_os = "linux")]
    #[test]
    fn bad_values_name_the_key() {
        let lo = || Xdp {
            interface: Some("lo".into()),
            ..Xdp::default()
        };
        let err = |x: Xdp| x.plan(8080, 0).unwrap_err();
        let x = Xdp {
            allow: vec!["nope".into()],
            ..lo()
        };
        assert!(err(x).contains("xdp.allow"));
        assert!(
            err(Xdp { burst: 0, ..lo() }).contains("xdp.burst"),
            "syn_pps is on by default"
        );
        assert!(
            err(Xdp {
                prefix_v4: 33,
                ..lo()
            })
            .contains("xdp.prefix_v4")
        );
        assert!(
            err(Xdp {
                prefix_v6: 129,
                ..lo()
            })
            .contains("xdp.prefix_v6")
        );
        assert!(
            err(Xdp {
                max_sources: 0,
                ..lo()
            })
            .contains("xdp.max_sources")
        );
        let x = Xdp {
            block: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
            max_blocks: 1,
            ..lo()
        };
        assert!(err(x).contains("over xdp.max_blocks (1)"));
        // every rate off: no bucket, so no burst needed
        let off = Xdp {
            burst: 0,
            syn_pps: 0,
            ..lo()
        };
        assert!(!off.plan(8080, 0).unwrap().unwrap().config.enforce);
        for (mode, attach) in [
            (AttachMode::Auto, Attach::Auto),
            (AttachMode::Native, Attach::Native),
            (AttachMode::Generic, Attach::Generic),
        ] {
            let x = Xdp {
                attach: mode,
                ..lo()
            };
            assert_eq!(x.plan(8080, 0).unwrap().unwrap().attach, attach);
        }
    }
}
