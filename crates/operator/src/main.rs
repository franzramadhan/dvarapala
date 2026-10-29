//! The operator binary: webhook, controller and metrics in one process.

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

fn args(mut a: impl Iterator<Item = String>) -> Option<Args> {
    let mut image = None;
    let mut webhook = SocketAddr::from(([0, 0, 0, 0], 9443));
    let mut metrics = SocketAddr::from(([0, 0, 0, 0], 9090));
    while let Some(k) = a.next() {
        let v = a.next()?;
        match k.as_str() {
            "--gateway-image" => image = Some(v),
            "--webhook-listen" => webhook = v.parse().ok()?,
            "--metrics-listen" => metrics = v.parse().ok()?,
            _ => return None,
        }
    }
    Some(Args {
        image: image?,
        webhook,
        metrics,
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
async fn run(a: Args) -> Result<(), Box<dyn Error>> {
    // the kube client's TLS takes the process default
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ns = std::env::var("POD_NAMESPACE").map_err(|_| "POD_NAMESPACE is not set")?;
    let client = Client::try_default().await?;
    let names = [
        NAME.to_owned(),
        format!("{NAME}.{ns}.svc"),
        format!("{NAME}.{ns}.svc.cluster.local"),
    ];
    let pem = cert::ensure(&client, &ns, &format!("{NAME}-tls"), &names).await?;
    cert::trust(&client, NAME, &pem.cert).await?;
    let tls = TlsAcceptor::from(cert::server_config(&pem)?);

    let prom = PrometheusBuilder::new().install_recorder()?;
    server::serve(a.metrics, None, move |path, _| {
        let prom = prom.clone();
        async move {
            match path.as_str() {
                "/metrics" => server::ok(prom.render().into_bytes(), "text/plain; version=0.0.4"),
                "/healthz" => server::ok(b"ok".to_vec(), "text/plain"),
                _ => server::status(StatusCode::NOT_FOUND),
            }
        }
    })
    .await?;

    let wc = client.clone();
    server::serve(a.webhook, Some(tls), move |path, body| {
        let wc = wc.clone();
        async move {
            match path.as_str() {
                "/mutate" => server::ok(webhook::review(&wc, &body).await, "application/json"),
                _ => server::status(StatusCode::NOT_FOUND),
            }
        }
    })
    .await?;

    let kinds = controller::kinds(&client).await;
    let ctx = Arc::new(Ctx {
        client,
        image: a.image,
        kinds,
    });
    tokio::select! {
        () = controller::run(ctx) => Err("controller stopped".into()),
        r = tokio::signal::ctrl_c() => r.map_err(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Option<Args> {
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
    }
}
