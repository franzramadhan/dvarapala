//! `mode` and the `[forward]` section (RFC 0007).

use std::time::Duration;

use dvarapala_engine::{Cidr, ScheduleConfig};
use dvarapala_proxy::Destination;
use serde::{Deserialize, Serialize};

use super::duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    #[default]
    Reverse,
    Forward,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Forward {
    pub clients: Vec<String>,
    pub connect: bool,
    pub destinations: Vec<ForwardDestination>,
}

impl Default for Forward {
    fn default() -> Self {
        Self {
            clients: vec!["127.0.0.0/8".into(), "::1/128".into()],
            connect: true,
            destinations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardDestination {
    pub origin: String,
    /// Defaults to the origin's host.
    pub name: Option<String>,
    pub rate: f64,
    #[serde(default = "one")]
    pub burst: u32,
    #[serde(default)]
    pub max_concurrent: usize,
    #[serde(default = "hundred")]
    pub max_queue: usize,
    #[serde(
        default = "two_seconds",
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub max_wait: Duration,
    #[serde(
        default = "a_minute",
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub max_pause: Duration,
}

fn one() -> u32 {
    1
}
fn hundred() -> usize {
    100
}
fn two_seconds() -> Duration {
    Duration::from_secs(2)
}
fn a_minute() -> Duration {
    Duration::from_secs(60)
}

impl Forward {
    /// The client CIDRs and the destinations; at least one destination.
    pub fn parts(&self) -> Result<(Vec<Cidr>, Vec<Destination>), String> {
        if self.destinations.is_empty() {
            return Err("mode = \"forward\" needs at least one [[forward.destinations]]".into());
        }
        let clients = self
            .clients
            .iter()
            .map(|c| {
                c.parse::<Cidr>()
                    .map_err(|e| format!("forward.clients: {e}"))
            })
            .collect::<Result<_, _>>()?;
        let destinations = self
            .destinations
            .iter()
            .map(|d| Destination {
                name: d.name.clone().unwrap_or_else(|| host(&d.origin)),
                origin: d.origin.clone(),
                schedule: ScheduleConfig {
                    rate: d.rate,
                    burst: d.burst,
                    max_queue: d.max_queue,
                    max_wait: d.max_wait,
                    max_pause: d.max_pause,
                },
                max_concurrent: d.max_concurrent,
            })
            .collect();
        Ok((clients, destinations))
    }
}

/// The host of `origin`, or `origin` itself when it does not parse (the
/// proxy then rejects it with the reason).
fn host(origin: &str) -> String {
    origin
        .parse::<hyper::Uri>()
        .ok()
        .and_then(|u| u.host().map(str::to_owned))
        .unwrap_or_else(|| origin.to_owned())
}
