//! RFC 0007 case 8: TLS origination to `https://` destinations.
#![cfg(feature = "tls")]

mod egress;
mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use dvarapala_proxy::ForwardConfig;
use dvarapala_proxy::tls::UpstreamTls;
use egress::{dest, get, proxy};
use http::StatusCode;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use support::{Ca, der, serve_one, tempdir, write};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// HTTPS upstream for 127.0.0.1 answering "secure".
async fn tls_upstream(ca: &Ca) -> SocketAddr {
    let (cert, key) = ca.leaf(&["127.0.0.1"]);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der(&cert)],
            PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(s) = acceptor.accept(s).await {
                    serve_one(TokioIo::new(s), "secure").await;
                }
            });
        }
    });
    addr
}

/// RFC 0007 case 8
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0007"]
async fn https_destination_is_verified() {
    let ca = Ca::new();
    let up = tls_upstream(&ca).await;
    let origin = format!("https://{up}");
    let with = |tls| ForwardConfig {
        tls,
        ..egress::config(vec![dest("c8", &origin, 100.0, 10)])
    };
    let trusted = UpstreamTls {
        ca_file: Some(write(&tempdir(), "ca.pem", &ca.pem)),
        server_name: None,
    };
    let (p, _stop) = proxy(with(trusted)).await;
    let (status, _, body) = get(p, &format!("{origin}/")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "secure"));
    let (p, _stop) = proxy(with(UpstreamTls::default())).await;
    assert_eq!(
        get(p, &format!("{origin}/")).await.0,
        StatusCode::BAD_GATEWAY
    );
}
