use std::num::NonZeroUsize;
use std::str::FromStr;
use std::time::Duration;

use dvarapala_engine::{
    ChallengeMode, Cidr, ConnsConfig, DetectConfig, GuardConfig, GuardDetection, Limit,
    TrustedProxies,
};

/// What a guard is built from: `CONFIG.md` key names and string values.
#[derive(Debug, Default, Clone)]
pub(crate) struct Settings(pub(crate) Vec<(String, String)>);

/// The guard's parts, validated.
#[derive(Debug)]
pub(crate) struct Built {
    pub(crate) guard: GuardConfig,
    pub(crate) trusted: TrustedProxies,
    /// `None` with `l4.enabled = false`
    pub(crate) conns: Option<ConnsConfig>,
    /// 0 off
    pub(crate) max_connections: usize,
}

/// Sections and keys that belong to the gateway's own server.
const NOT_IN_PROCESS: [&str; 14] = [
    "mode",
    "listen",
    "upstream",
    "upstream_protocol",
    "metrics.",
    "ml.",
    "tls.",
    "upstream_tls.",
    "http2.",
    "upgrade.",
    "forward.",
    "l4.header_timeout",
    "l4.idle_timeout",
    "l4.min_body_rate",
];

impl Settings {
    /// The parts, with the gateway's defaults, or an error naming the key.
    pub(crate) fn build(&self) -> Result<Built, String> {
        let (mut rate, mut burst, mut max_clients) = (20, 40, 100_000);
        let (mut detection, mut enforce, mut factor) = (true, false, 0.25);
        let mut d = DetectConfig::default();
        let mut trusted = Vec::new();
        let (mut l4, mut max_connections) = (true, 0);
        let mut c = ConnsConfig::default();
        let (mut accept_rate, mut accept_burst) = (0, 64);
        for (k, v) in &self.0 {
            let k = k.as_str();
            match k {
                "rate_limit.rate" => rate = num(k, v)?,
                "rate_limit.burst" => burst = num(k, v)?,
                "rate_limit.max_clients" => max_clients = num(k, v)?,
                "trusted_proxies" => trusted = cidrs(k, v)?,
                "detection.enabled" => detection = num(k, v)?,
                "detection.mode" => {
                    enforce = match v.as_str() {
                        "observe" => false,
                        "enforce" => true,
                        _ => return Err(format!("{k}: {v:?} is not \"observe\" or \"enforce\"")),
                    }
                }
                "detection.window" => d.window = duration(k, v)?,
                "detection.prefix_v4" => d.prefix_v4 = num(k, v)?,
                "detection.prefix_v6" => d.prefix_v6 = num(k, v)?,
                "detection.sketch_width" => d.sketch_width = num(k, v)?,
                "detection.sketch_depth" => d.sketch_depth = num(k, v)?,
                "detection.top_k" => d.top_k = num(k, v)?,
                "detection.ewma_alpha" => d.ewma_alpha = num(k, v)?,
                "detection.warmup_windows" => d.warmup_windows = num(k, v)?,
                "detection.z_threshold" => d.z_threshold = num(k, v)?,
                "detection.entropy_buckets" => d.entropy_buckets = num(k, v)?,
                "detection.entropy_drop" => d.entropy_drop = num(k, v)?,
                "detection.trigger_windows" => d.trigger_windows = num(k, v)?,
                "detection.cooldown_windows" => d.cooldown_windows = num(k, v)?,
                "detection.attack_rate_factor" => factor = num(k, v)?,
                "l4.enabled" => l4 = num(k, v)?,
                "l4.max_connections" => max_connections = num(k, v)?,
                "l4.max_per_client" => c.max_per_client = num(k, v)?,
                "l4.accept_rate" => accept_rate = num(k, v)?,
                "l4.accept_burst" => accept_burst = num(k, v)?,
                "l4.prefix_v4" => c.prefix_v4 = num(k, v)?,
                "l4.prefix_v6" => c.prefix_v6 = num(k, v)?,
                "l4.max_clients" => {
                    c.max_clients = NonZeroUsize::new(num(k, v)?)
                        .ok_or_else(|| format!("{k} must be at least 1"))?;
                }
                "l4.exempt" => c.exempt = cidrs(k, v)?,
                _ if NOT_IN_PROCESS
                    .iter()
                    .any(|p| k == *p || (p.ends_with('.') && k.starts_with(p))) =>
                {
                    return Err(format!("{k} does not apply in-process"));
                }
                _ => return Err(format!("{k} is not a key")),
            }
        }
        let limit = Limit::new(rate, burst).map_err(|e| format!("rate_limit.rate: {e}"))?;
        c.accept = match accept_rate {
            0 => None,
            r => Some(Limit::new(r, accept_burst).map_err(|e| format!("l4.accept_rate: {e}"))?),
        };
        Ok(Built {
            guard: GuardConfig {
                limit,
                max_clients: NonZeroUsize::new(max_clients)
                    .ok_or("rate_limit.max_clients must be at least 1")?,
                detection: detection.then_some(GuardDetection {
                    detect: d,
                    enforce,
                    attack_rate_factor: factor,
                }),
                // RFC 0008: no challenge page in process
                challenge: ChallengeMode::Off,
            },
            trusted: TrustedProxies::new(trusted),
            conns: l4.then_some(c),
            max_connections: if l4 { max_connections } else { 0 },
        })
    }
}

fn num<T: FromStr>(k: &str, v: &str) -> Result<T, String> {
    v.trim()
        .parse()
        .map_err(|_| format!("{k}: invalid value {v:?}"))
}

/// Comma-separated CIDRs.
fn cidrs(k: &str, v: &str) -> Result<Vec<Cidr>, String> {
    v.split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| c.parse().map_err(|e| format!("{k}: {e}")))
        .collect()
}

/// `"<n>ms"`, `"<n>s"`, `"<n>m"` or `"<n>h"`, as in the gateway's config.
fn duration(k: &str, v: &str) -> Result<Duration, String> {
    let units = [("ms", 1), ("s", 1_000), ("m", 60_000), ("h", 3_600_000)];
    units
        .iter()
        .find_map(|(u, ms)| {
            let n: u32 = v.strip_suffix(u)?.parse().ok()?;
            Some(Duration::from_millis(*ms) * n)
        })
        .ok_or_else(|| format!("{k}: invalid duration {v:?}, use for example \"500ms\" or \"1s\""))
}
