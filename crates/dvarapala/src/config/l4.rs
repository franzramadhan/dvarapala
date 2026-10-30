//! The `[l4]` section (RFC 0009).

use std::num::NonZeroUsize;
use std::time::Duration;

use dvarapala_engine::{Cidr, ConnsConfig, Limit};
use dvarapala_l4::L4Config;
use serde::{Deserialize, Serialize};

use super::duration;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct L4 {
    pub enabled: bool,
    pub max_connections: usize,
    pub max_per_client: u32,
    pub accept_rate: u32,
    pub accept_burst: u32,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub max_clients: usize,
    pub exempt: Vec<String>,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub header_timeout: Duration,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub idle_timeout: Duration,
    pub min_body_rate: u64,
}

impl Default for L4 {
    fn default() -> Self {
        Self {
            enabled: true,
            max_connections: 0,
            max_per_client: 256,
            accept_rate: 0,
            accept_burst: 64,
            prefix_v4: 32,
            prefix_v6: 64,
            max_clients: 100_000,
            exempt: Vec::new(),
            header_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            min_body_rate: 0,
        }
    }
}

impl L4 {
    /// The listener config; prefixes are checked by the listener.
    pub fn config(&self) -> Result<L4Config, String> {
        let accept = match self.accept_rate {
            0 => None,
            r => {
                Some(Limit::new(r, self.accept_burst).map_err(|e| format!("l4.accept_rate: {e}"))?)
            }
        };
        let exempt = self
            .exempt
            .iter()
            .map(|c| c.parse::<Cidr>().map_err(|e| format!("l4.exempt: {e}")))
            .collect::<Result<_, _>>()?;
        if self.header_timeout.is_zero() {
            return Err("l4.header_timeout must be more than 0s".into());
        }
        Ok(L4Config {
            enabled: self.enabled,
            max_connections: self.max_connections,
            conns: ConnsConfig {
                max_per_client: self.max_per_client,
                accept,
                prefix_v4: self.prefix_v4,
                prefix_v6: self.prefix_v6,
                max_clients: NonZeroUsize::new(self.max_clients)
                    .ok_or("l4.max_clients must be at least 1")?,
                exempt,
            },
            header_timeout: self.header_timeout,
            idle_timeout: (!self.idle_timeout.is_zero()).then_some(self.idle_timeout),
            min_body_rate: self.min_body_rate,
        })
    }
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use std::path::Path;

    use figment::Jail;

    use super::*;

    /// RFC 0009 configuration table.
    #[test]
    fn defaults_and_section() {
        let d = L4::default().config().unwrap();
        assert_eq!(d, L4Config::default());
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\n[l4]\nmax_connections = 10000\nmax_per_client = 0\naccept_rate = 10\naccept_burst = 20\nprefix_v6 = 56\nexempt = [\"192.0.2.0/24\"]\nheader_timeout = \"5s\"\nidle_timeout = \"0s\"\nmin_body_rate = 100\n",
            )?;
            let c = crate::config::load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            let l = c.l4.config()?;
            assert_eq!(l.max_connections, 10_000);
            assert_eq!(l.conns.max_per_client, 0);
            assert_eq!(l.conns.accept, Some(Limit::new(10, 20).unwrap()));
            assert_eq!((l.conns.prefix_v4, l.conns.prefix_v6), (32, 56));
            assert_eq!(
                l.conns.exempt,
                vec!["192.0.2.0/24".parse::<Cidr>().unwrap()]
            );
            assert_eq!(l.header_timeout, Duration::from_secs(5));
            assert_eq!(l.idle_timeout, None);
            assert_eq!(l.min_body_rate, 100);
            Ok(())
        });
    }

    #[test]
    fn bad_values_name_the_key() {
        let bad = |l: L4| l.config().unwrap_err();
        assert!(
            bad(L4 {
                exempt: vec!["nope".into()],
                ..L4::default()
            })
            .contains("l4.exempt")
        );
        assert!(
            bad(L4 {
                max_clients: 0,
                ..L4::default()
            })
            .contains("l4.max_clients")
        );
        assert!(
            bad(L4 {
                header_timeout: Duration::ZERO,
                ..L4::default()
            })
            .contains("header_timeout")
        );
    }
}
