//! The operator's process, after the client: the webhook certificate, the
//! metrics and webhook listeners, and the controller's context.

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::StatusCode;
use kube::Client;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio_rustls::TlsAcceptor;

use crate::controller::{self, Ctx};
use crate::{cert, server, webhook};

/// The Service and `MutatingWebhookConfiguration` of `deploy/operator.yaml`.
pub const NAME: &str = "dvarapala-operator";

pub struct Options {
    pub image: String,
    pub webhook: SocketAddr,
    pub metrics: SocketAddr,
    /// RFC 0025: the prefixes a WAF sidecar image needs.
    pub waf_images: Vec<String>,
}

pub struct Started {
    pub ctx: Arc<Ctx>,
    pub webhook: SocketAddr,
    pub metrics: SocketAddr,
}

/// Everything but the controller loop, in namespace `ns`: the certificate
/// in its Secret and trusted by the webhook configuration, then both
/// listeners, then the route kinds the cluster serves.
pub async fn start(
    client: Client,
    ns: &str,
    o: Options,
    prom: PrometheusHandle,
) -> Result<Started, Box<dyn Error>> {
    let names = [
        NAME.to_owned(),
        format!("{NAME}.{ns}.svc"),
        format!("{NAME}.{ns}.svc.cluster.local"),
    ];
    let pem = cert::ensure(&client, ns, &format!("{NAME}-tls"), &names).await?;
    cert::trust(&client, NAME, &pem.cert).await?;
    let tls = TlsAcceptor::from(cert::server_config(&pem)?);

    let metrics = server::serve(o.metrics, None, move |path, _| {
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
    let webhook = server::serve(o.webhook, Some(tls), move |path, body| {
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
        image: o.image,
        kinds,
        waf_images: o.waf_images,
    });
    Ok(Started {
        ctx,
        webhook,
        metrics,
    })
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
