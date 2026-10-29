//! The operator binary: webhook, controller and metrics in one process.
#![allow(unused_variables, unused_imports, dead_code)]

use std::error::Error;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use dvarapala_operator::controller::{self, Ctx};
use dvarapala_operator::crd::DvarapalaPolicy;
use dvarapala_operator::{cert, server, webhook};
use hyper::StatusCode;
use kube::{Client, CustomResourceExt};
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: dvarapala-operator run --gateway-image <image> [--webhook-listen <addr>] [--metrics-listen <addr>]
       dvarapala-operator crd
       dvarapala-operator --version
The namespace comes from POD_NAMESPACE. Log level comes from RUST_LOG (default info).";

/// The Service and `MutatingWebhookConfiguration` of `deploy/operator.yaml`.
const NAME: &str = "dvarapala-operator";

struct Args {
    image: String,
    webhook: SocketAddr,
    metrics: SocketAddr,
}

fn args(a: impl Iterator<Item = String>) -> Option<Args> {
    todo!("rfc 0019")
}

fn main() -> ExitCode {
    todo!("rfc 0019")
}

#[tokio::main]
async fn run(a: Args) -> Result<(), Box<dyn Error>> {
    todo!("rfc 0019")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Option<Args> {
        args(s.split_whitespace().map(str::to_owned))
    }

    #[test]
    #[ignore = "rfc 0019"]
    fn flags() {
        let a = parse("--gateway-image dvarapala:0.12.0").unwrap();
        assert_eq!(a.image, "dvarapala:0.12.0");
        assert_eq!((a.webhook.port(), a.metrics.port()), (9443, 9090));
        let a =
            parse("--webhook-listen 127.0.0.1:1 --gateway-image x --metrics-listen 127.0.0.1:2")
                .unwrap();
        assert_eq!((a.webhook.port(), a.metrics.port()), (1, 2));
        assert!(parse("").is_none(), "the image is required");
        assert!(parse("--gateway-image").is_none());
        assert!(parse("--gateway-image x --nope y").is_none());
        assert!(parse("--gateway-image x --webhook-listen nope").is_none());
    }
}
