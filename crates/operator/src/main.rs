//! The operator binary: webhook, controller and metrics in one process.

use std::error::Error;
use std::net::SocketAddr;
use std::process::ExitCode;

use dvarapala_operator::app::{self, Options};
use dvarapala_operator::controller;
use dvarapala_operator::crd::DvarapalaPolicy;
use kube::{Client, CustomResourceExt};
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: dvarapala-operator run --gateway-image <image> [--webhook-listen <addr>] [--metrics-listen <addr>] [--waf-images <prefix,...>]
       [--mount-images <prefix,...>]
       dvarapala-operator crd
       dvarapala-operator --version
The namespace comes from POD_NAMESPACE. Log level comes from RUST_LOG (default info).";

/// RFC 0025: the WAF sidecar images a policy may name, by default.
const WAF_IMAGES: &str = "ghcr.io/corazawaf/coraza-spoa";

/// Comma separated, blanks dropped: an empty flag allows no image.
fn prefixes(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

fn args(mut a: impl Iterator<Item = String>) -> Option<Options> {
    let mut image = None;
    let mut webhook = SocketAddr::from(([0, 0, 0, 0], 9443));
    let mut metrics = SocketAddr::from(([0, 0, 0, 0], 9090));
    let mut waf_images = prefixes(WAF_IMAGES);
    let mut mount_images = Vec::new();
    while let Some(k) = a.next() {
        let v = a.next()?;
        match k.as_str() {
            "--gateway-image" => image = Some(v),
            "--webhook-listen" => webhook = v.parse().ok()?,
            "--metrics-listen" => metrics = v.parse().ok()?,
            "--waf-images" => waf_images = prefixes(&v),
            "--mount-images" => mount_images = prefixes(&v),
            _ => return None,
        }
    }
    Some(Options {
        image: image?,
        webhook,
        metrics,
        waf_images,
        mount_images,
    })
}

fn main() -> ExitCode {
    let mut a = std::env::args().skip(1);
    let parsed = match a.next().as_deref() {
        Some("run") => args(a),
        Some("crd") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&DvarapalaPolicy::crd()).unwrap_or_default()
            );
            return ExitCode::SUCCESS;
        }
        Some("--version") => {
            println!("dvarapala-operator {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => None,
    };
    let Some(parsed) = parsed else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match run(parsed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dvarapala-operator: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn run(o: Options) -> Result<(), Box<dyn Error>> {
    // the kube client's TLS takes the process default
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ns = std::env::var("POD_NAMESPACE").map_err(|_| "POD_NAMESPACE is not set")?;
    let client = Client::try_default().await?;
    let prom = PrometheusBuilder::new().install_recorder()?;
    let started = app::start(client, &ns, o, prom).await?;
    tokio::select! {
        () = controller::run(started.ctx) => Err("controller stopped".into()),
        r = tokio::signal::ctrl_c() => r.map_err(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Option<Options> {
        args(s.split_whitespace().map(str::to_owned))
    }

    #[test]
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
        assert_eq!(a.waf_images, ["ghcr.io/corazawaf/coraza-spoa"]);
        let a = parse("--gateway-image x --waf-images a/b,,c/d").unwrap();
        assert_eq!(a.waf_images, ["a/b", "c/d"]);
        // an empty value refuses every sidecar
        let a = args(
            ["--gateway-image", "x", "--waf-images", ""]
                .map(String::from)
                .into_iter(),
        )
        .unwrap();
        assert!(a.waf_images.is_empty());
        // RFC 0033: image mounts are refused until a prefix is named
        assert!(a.mount_images.is_empty());
        let a = parse("--gateway-image x --mount-images registry.example/geo/,b").unwrap();
        assert_eq!(a.mount_images, ["registry.example/geo/", "b"]);
    }
}
