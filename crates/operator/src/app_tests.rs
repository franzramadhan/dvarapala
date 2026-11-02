use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::ObjectMeta;
use metrics_exporter_prometheus::PrometheusBuilder;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::*;
use crate::fake::Fake;

const HOOK: &str =
    "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/dvarapala-operator";

/// A cluster with the operator's Secret holding a pair for `localhost`,
/// its webhook configuration, and HTTPRoute served (GRPCRoute not).
fn cluster() -> (Fake, cert::Pem) {
    let fake = Fake::default();
    let pem = cert::generate(&["localhost".into()]).unwrap();
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(format!("{NAME}-tls")),
            ..ObjectMeta::default()
        },
        data: Some(BTreeMap::from([
            ("tls.crt".into(), ByteString(pem.cert.clone().into_bytes())),
            ("tls.key".into(), ByteString(pem.key.clone().into_bytes())),
        ])),
        ..Secret::default()
    };
    fake.put(
        "/api/v1/namespaces/dvarapala/secrets/dvarapala-operator-tls",
        serde_json::to_value(&secret).unwrap(),
    );
    fake.put(
        HOOK,
        json!({"apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": NAME},
            "webhooks": [{"name": "mutate.dvarapala.franzramadhan.dev", "clientConfig": {},
                "admissionReviewVersions": ["v1"], "sideEffects": "None"}]}),
    );
    fake.put(
        "/apis/gateway.networking.k8s.io/v1",
        json!({"kind": "APIResourceList", "apiVersion": "v1",
            "groupVersion": "gateway.networking.k8s.io/v1",
            "resources": [{"name": "httproutes", "singularName": "httproute",
                "namespaced": true, "kind": "HTTPRoute", "verbs": ["get", "list", "watch"]}]}),
    );
    (fake, pem)
}

fn options() -> Options {
    let any = SocketAddr::from(([127, 0, 0, 1], 0));
    Options {
        image: "dvarapala:test".into(),
        webhook: any,
        metrics: any,
        waf_images: vec!["ghcr.io/corazawaf/coraza-spoa".into()],
        mount_images: Vec::new(),
    }
}

fn prom() -> PrometheusHandle {
    PrometheusBuilder::new().build_recorder().handle()
}

/// One request over `io`, the whole response back as text.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    method: &str,
    path: &str,
    body: &[u8],
) -> String {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    // a server that hangs up early answers nothing, which the caller checks
    let _ = io.write_all(head.as_bytes()).await;
    let _ = io.write_all(body).await;
    let mut out = Vec::new();
    let _ = io.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn plain(addr: SocketAddr, path: &str) -> String {
    exchange(TcpStream::connect(addr).await.unwrap(), "GET", path, b"").await
}

async fn tls(addr: SocketAddr, pem: &cert::Pem, path: &str, body: &[u8]) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pem.cert.as_bytes()).unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let io = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    exchange(io, "POST", path, body).await
}

#[tokio::test]
async fn serves_metrics_and_the_webhook() {
    let (fake, pem) = cluster();
    let s = start(fake.client(), "dvarapala", options(), prom())
        .await
        .unwrap();
    let kinds: Vec<_> = s.ctx.kinds.iter().map(|(k, _)| k.name()).collect();
    assert_eq!(kinds, ["Ingress", "HTTPRoute"]);
    assert_eq!(s.ctx.image, "dvarapala:test");

    assert!(
        plain(s.metrics, "/healthz")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        plain(s.metrics, "/metrics")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(plain(s.metrics, "/nope").await.starts_with("HTTP/1.1 404"));

    let out = tls(s.webhook, &pem, "/mutate", b"{").await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains(r#""allowed":false"#), "{out}");
    assert!(
        tls(s.webhook, &pem, "/nope", b"")
            .await
            .starts_with("HTTP/1.1 404")
    );

    // a client that does not speak TLS gets no answer
    let out = plain(s.webhook, "/mutate").await;
    assert!(!out.starts_with("HTTP/1.1"), "{out}");

    // the configuration now trusts the pair
    assert_eq!(
        fake.writes(),
        [format!("PUT {HOOK}")],
        "the existing Secret is reused"
    );
}

#[tokio::test]
async fn start_fails_without_the_webhook_configuration() {
    let fake = Fake::default();
    let e = start(fake.client(), "dvarapala", options(), prom())
        .await
        .err()
        .unwrap();
    assert!(e.to_string().starts_with("dvarapala-operator: "), "{e}");
}

#[tokio::test]
async fn start_fails_when_a_port_is_taken() {
    let (fake, _) = cluster();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let o = Options {
        metrics: taken.local_addr().unwrap(),
        ..options()
    };
    assert!(start(fake.client(), "dvarapala", o, prom()).await.is_err());
}
