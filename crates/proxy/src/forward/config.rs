use std::fmt;
use std::sync::{Arc, Mutex};

use dvarapala_engine::{Cidr, Cluster, ScheduleConfig};

use crate::UpgradeConfig;

/// One destination on the allow list.
#[derive(Debug, Clone, PartialEq)]
pub struct Destination {
    /// Label in logs and metrics.
    pub name: String,
    /// `http://host[:port]` or `https://host[:port]`.
    pub origin: String,
    pub schedule: ScheduleConfig,
    /// Requests or tunnels in flight at once; 0 off.
    pub max_concurrent: usize,
}

/// The forward proxy: who may use it and where requests may go.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Peers allowed to use the proxy.
    pub clients: Vec<Cidr>,
    /// Allow `CONNECT` to listed destinations.
    pub connect: bool,
    pub destinations: Vec<Destination>,
    /// Limits for `CONNECT` tunnels (RFC 0005).
    pub tunnels: UpgradeConfig,
    /// Verification of `https://` destinations (RFC 0003).
    #[cfg(feature = "tls")]
    pub tls: crate::tls::UpstreamTls,
    /// RFC 0010: budgets split by live replicas and pauses shared; `None`
    /// keeps each destination's budget to this process.
    pub cluster: Option<Arc<Mutex<Cluster>>>,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            clients: vec![
                "127.0.0.0/8".parse().expect("valid"),
                "::1/128".parse().expect("valid"),
            ],
            connect: true,
            destinations: Vec::new(),
            tunnels: UpgradeConfig::default(),
            #[cfg(feature = "tls")]
            tls: crate::tls::UpstreamTls::default(),
            cluster: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /// A destination's origin is not `http(s)://host[:port]`, or repeats one.
    Origin(String),
    /// A destination's limits are invalid.
    Schedule(String),
    /// `https://` without the `tls` feature.
    Unsupported(String),
    /// The upstream TLS settings could not be loaded.
    Tls(String),
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Origin(why) => write!(f, "forward destination: {why}"),
            Self::Schedule(why) => write!(f, "forward destination limits: {why}"),
            Self::Unsupported(o) => write!(f, "destination {o:?}: https:// needs the tls feature"),
            Self::Tls(why) => write!(f, "upstream tls: {why}"),
        }
    }
}

impl std::error::Error for ForwardError {}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::Empty;

    use super::*;
    use crate::ForwardProxy;

    fn refused(config: ForwardConfig) -> String {
        ForwardProxy::<Empty<Bytes>>::new(&config)
            .err()
            .expect("refused")
            .to_string()
    }

    fn dest(origin: &str, rate: f64) -> Destination {
        Destination {
            name: "d".into(),
            origin: origin.into(),
            schedule: ScheduleConfig {
                rate,
                ..ScheduleConfig::default()
            },
            max_concurrent: 0,
        }
    }

    fn config(destinations: Vec<Destination>) -> ForwardConfig {
        ForwardConfig {
            destinations,
            ..ForwardConfig::default()
        }
    }

    #[test]
    fn errors_name_the_destination() {
        let e = refused(config(vec![dest("ftp://x.example", 1.0)]));
        assert!(
            e.starts_with("forward destination: origin \"ftp://x.example\""),
            "{e}"
        );
        let e = refused(config(vec![dest("http://x.example", 0.0)]));
        assert!(e.starts_with("forward destination limits: d: "), "{e}");
        assert_eq!(
            ForwardError::Unsupported("https://x.example".into()).to_string(),
            "destination \"https://x.example\": https:// needs the tls feature"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_ca_file_without_certificates_is_refused() {
        let ca = std::env::temp_dir().join(format!("dvarapala-fwd-ca-{}.pem", std::process::id()));
        std::fs::write(&ca, "").unwrap();
        let mut c = config(vec![dest("https://x.example", 1.0)]);
        c.tls.ca_file = Some(ca.clone());
        let e = refused(c);
        std::fs::remove_file(&ca).unwrap();
        assert!(e.starts_with("upstream tls: "), "{e}");
        assert!(e.ends_with(": no certificates"), "{e}");
    }
}
