//! Config from a TOML file, overridden by `DVARAPALA__*` environment
//! variables (`DVARAPALA__RATE_LIMIT__RATE=5` sets `rate_limit.rate`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use dvarapala_engine::DetectConfig;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::{Deserialize, Deserializer, de};

mod challenge;
mod forward;
mod l4;
mod protocols;
mod quic;
mod store;
mod tls;
mod xdp;
pub use challenge::{Challenge, Fingerprint};
pub use forward::{Forward, ProxyMode};
pub use l4::L4;
pub use protocols::{Http2, Upgrade, UpstreamProtocol};
pub use quic::Quic;
#[cfg(feature = "http3")]
pub use quic::{QuicPlan, QuicRetry};
pub use store::{Backend, Store};
pub use tls::{Tls, UpstreamTls};
pub use xdp::{Xdp, XdpPlan};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mode: ProxyMode,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Required in reverse mode, ignored in forward mode.
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstream_protocol: UpstreamProtocol,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub rate_limit: RateLimit,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub detection: Detection,
    #[serde(default)]
    pub ml: Ml,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub upstream_tls: UpstreamTls,
    #[serde(default)]
    pub http2: Http2,
    #[serde(default)]
    pub upgrade: Upgrade,
    #[serde(default)]
    pub forward: Forward,
    #[serde(default)]
    pub l4: L4,
    #[serde(default)]
    pub quic: Quic,
    #[serde(default)]
    pub store: Store,
    #[serde(default)]
    pub xdp: Xdp,
    #[serde(default)]
    pub challenge: Challenge,
    #[serde(default)]
    pub fingerprint: Fingerprint,
}

impl Config {
    /// `upstream`, required in reverse mode.
    pub fn reverse_upstream(&self) -> Result<&str, String> {
        self.upstream
            .as_deref()
            .ok_or_else(|| "upstream is required with mode = \"reverse\"".into())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Metrics {
    /// Empty turns the endpoint off.
    pub listen: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimit {
    pub enabled: bool,
    pub rate: u32,
    pub burst: u32,
    pub max_clients: usize,
}

/// RFC 0002 keys. Defaults come from [`DetectConfig::default`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Detection {
    pub enabled: bool,
    pub mode: Mode,
    #[serde(deserialize_with = "duration")]
    pub window: Duration,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub sketch_width: usize,
    pub sketch_depth: usize,
    pub top_k: usize,
    pub ewma_alpha: f64,
    pub warmup_windows: u32,
    pub z_threshold: f64,
    pub entropy_buckets: usize,
    pub entropy_drop: f64,
    pub trigger_windows: u32,
    pub cooldown_windows: u32,
    pub attack_rate_factor: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ml {
    /// XGBoost JSON model; unset turns scoring off.
    pub model: Option<PathBuf>,
    pub threshold: f64,
}

impl Default for Detection {
    fn default() -> Self {
        let d = DetectConfig::default();
        Self {
            enabled: true,
            mode: Mode::Observe,
            window: d.window,
            prefix_v4: d.prefix_v4,
            prefix_v6: d.prefix_v6,
            sketch_width: d.sketch_width,
            sketch_depth: d.sketch_depth,
            top_k: d.top_k,
            ewma_alpha: d.ewma_alpha,
            warmup_windows: d.warmup_windows,
            z_threshold: d.z_threshold,
            entropy_buckets: d.entropy_buckets,
            entropy_drop: d.entropy_drop,
            trigger_windows: d.trigger_windows,
            cooldown_windows: d.cooldown_windows,
            attack_rate_factor: 0.25,
        }
    }
}

impl Default for Ml {
    fn default() -> Self {
        Self {
            model: None,
            threshold: 0.9,
        }
    }
}

/// `"<n>ms"`, `"<n>s"`, `"<n>m"` or `"<n>h"`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let err = || format!("invalid duration {s:?}, use for example \"500ms\", \"1s\" or \"24h\"");
    let units = [("ms", 1), ("s", 1_000), ("m", 60_000), ("h", 3_600_000)];
    let (n, ms) = units
        .iter()
        .find_map(|(u, ms)| Some((s.strip_suffix(u)?, *ms)))
        .ok_or_else(err)?;
    let unit = Duration::from_millis(ms);
    // u32 parsing rejects signs, fractions and spaces
    let n: u32 = n.parse().map_err(|_| err())?;
    Ok(unit * n)
}

fn duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    parse_duration(&String::deserialize(d)?).map_err(de::Error::custom)
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9090".into(),
        }
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            rate: 20,
            burst: 40,
            max_clients: 100_000,
        }
    }
}

/// Reads `path` (when given) and the environment.
pub fn load(path: Option<&Path>) -> Result<Config, Box<figment::Error>> {
    let mut f = Figment::new();
    if let Some(path) = path {
        // file_exact: a missing --config file is an error, not an empty config
        f = f.merge(Toml::file_exact(path));
    }
    f.merge(Env::prefixed("DVARAPALA__").split("__"))
        .extract()
        .map_err(Box::new)
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;

    #[test]
    fn env_overrides_file() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\n[rate_limit]\nrate = 50\n",
            )?;
            j.set_env("DVARAPALA__RATE_LIMIT__RATE", "5");
            let c = load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(c.rate_limit.rate, 5);
            assert_eq!(c.rate_limit.burst, 40);
            Ok(())
        });
    }

    #[test]
    fn missing_upstream_names_the_key() {
        Jail::expect_with(|j| {
            j.create_file("d.toml", "listen = \"127.0.0.1:8080\"\n")?;
            let c = load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            let e = c.reverse_upstream().unwrap_err();
            assert!(e.contains("upstream"), "{e}");
            Ok(())
        });
    }

    /// RFC 0007 configuration table.
    #[test]
    fn forward_section() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "mode = \"forward\"\n[[forward.destinations]]\norigin = \"https://api.provider-a.example\"\nrate = 50\n[[forward.destinations]]\nname = \"b\"\norigin = \"http://192.0.2.1:8080\"\nrate = 0.5\nburst = 3\nmax_concurrent = 2\nmax_queue = 0\nmax_wait = \"500ms\"\nmax_pause = \"0s\"\n",
            )?;
            let c = load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(c.mode, ProxyMode::Forward);
            assert!(c.forward.connect);
            let (clients, ds) = c.forward.parts()?;
            assert_eq!(clients.len(), 2);
            assert_eq!(ds[0].name, "api.provider-a.example");
            assert_eq!(
                (
                    ds[0].schedule.rate,
                    ds[0].schedule.burst,
                    ds[0].schedule.max_queue
                ),
                (50.0, 1, 100)
            );
            assert_eq!(ds[0].schedule.max_wait, Duration::from_secs(2));
            assert_eq!(ds[0].schedule.max_pause, Duration::from_secs(60));
            assert_eq!(ds[0].max_concurrent, 0);
            assert_eq!(ds[1].name, "b");
            assert_eq!((ds[1].schedule.rate, ds[1].max_concurrent), (0.5, 2));
            assert_eq!(ds[1].schedule.max_pause, Duration::ZERO);
            Ok(())
        });
    }

    #[test]
    fn forward_needs_a_destination() {
        assert!(
            Forward::default()
                .parts()
                .unwrap_err()
                .contains("forward.destinations")
        );
    }

    #[test]
    fn defaults_match_the_rfc() {
        Jail::expect_with(|j| {
            j.set_env("DVARAPALA__UPSTREAM", "http://127.0.0.1:8081");
            let c = load(None).map_err(|e| e.to_string())?;
            assert_eq!(c.listen, "0.0.0.0:8080".parse().unwrap());
            assert_eq!(c.metrics.listen, "127.0.0.1:9090");
            assert_eq!(
                c.rate_limit,
                RateLimit {
                    enabled: true,
                    rate: 20,
                    burst: 40,
                    max_clients: 100_000
                }
            );
            assert!(c.trusted_proxies.is_empty());
            Ok(())
        });
    }

    #[test]
    fn unknown_key_is_an_error() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\nrate_limt = {}\n",
            )?;
            let e = load(Some(Path::new("d.toml"))).unwrap_err().to_string();
            assert!(e.contains("rate_limt"), "{e}");
            Ok(())
        });
    }

    #[test]
    fn detection_defaults_match_the_rfc() {
        Jail::expect_with(|j| {
            j.set_env("DVARAPALA__UPSTREAM", "http://127.0.0.1:8081");
            let c = load(None).map_err(|e| e.to_string())?;
            let d = &c.detection;
            assert!(d.enabled);
            assert_eq!(d.mode, Mode::Observe);
            assert_eq!(d.window, Duration::from_secs(1));
            assert_eq!((d.prefix_v4, d.prefix_v6), (32, 64));
            assert_eq!((d.sketch_width, d.sketch_depth, d.top_k), (2048, 4, 64));
            assert_eq!(
                (d.ewma_alpha, d.warmup_windows, d.z_threshold),
                (0.05, 300, 4.0)
            );
            assert_eq!((d.entropy_buckets, d.entropy_drop), (1024, 0.5));
            assert_eq!((d.trigger_windows, d.cooldown_windows), (3, 30));
            assert_eq!(d.attack_rate_factor, 0.25);
            assert_eq!(
                c.ml,
                Ml {
                    model: None,
                    threshold: 0.9
                }
            );
            Ok(())
        });
    }

    #[test]
    fn detection_from_file_and_env() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\n[detection]\nmode = \"enforce\"\nwindow = \"500ms\"\n",
            )?;
            j.set_env("DVARAPALA__DETECTION__PREFIX_V4", "24");
            let c = load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(c.detection.mode, Mode::Enforce);
            assert_eq!(c.detection.window, Duration::from_millis(500));
            assert_eq!(c.detection.prefix_v4, 24);
            Ok(())
        });
    }

    #[test]
    fn bad_mode_is_an_error() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\n[detection]\nmode = \"block\"\n",
            )?;
            let e = load(Some(Path::new("d.toml"))).unwrap_err().to_string();
            assert!(e.contains("block"), "{e}");
            Ok(())
        });
    }

    #[test]
    fn tls_defaults_match_the_rfc() {
        Jail::expect_with(|j| {
            j.set_env("DVARAPALA__UPSTREAM", "http://127.0.0.1:8081");
            let c = load(None).map_err(|e| e.to_string())?;
            assert_eq!((c.tls.cert.as_deref(), c.tls.key.as_deref()), (None, None));
            assert_eq!(c.tls.handshake_timeout, Duration::from_secs(10));
            assert_eq!(c.tls.max_handshakes, 1024);
            assert_eq!(c.upstream_tls, UpstreamTls::default());
            assert_eq!(c.tls.paths(), Ok(None));
            Ok(())
        });
    }

    #[test]
    fn tls_from_file() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"https://127.0.0.1:8443\"\n[tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nhandshake_timeout = \"2s\"\n[upstream_tls]\nserver_name = \"app.test\"\n",
            )?;
            let c = load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(
                c.tls.paths(),
                Ok(Some((Path::new("c.pem"), Path::new("k.pem"))))
            );
            assert_eq!(c.tls.handshake_timeout, Duration::from_secs(2));
            assert_eq!(c.upstream_tls.server_name.as_deref(), Some("app.test"));
            Ok(())
        });
    }

    #[test]
    fn tls_key_is_required_with_cert() {
        let t = Tls {
            cert: Some("c.pem".into()),
            ..Tls::default()
        };
        assert!(t.paths().unwrap_err().contains("tls.key"));
        let t = Tls {
            key: Some("k.pem".into()),
            ..Tls::default()
        };
        assert!(t.paths().unwrap_err().contains("tls.cert"));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1s"), Ok(Duration::from_secs(1)));
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("24h"), Ok(Duration::from_secs(86_400)));
        for bad in ["", "1", "s", "1d", "-1s", "1.5s", "1 s", "1hs"] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn example_configs_load() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        let mut n = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "toml") {
                load(Some(&path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                n += 1;
            }
        }
        assert!(n >= 4, "{n} examples");
    }
}
