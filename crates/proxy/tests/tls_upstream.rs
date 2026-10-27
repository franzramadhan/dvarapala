//! RFC 0003: `https://` upstreams.
#![cfg(feature = "tls")]

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dvarapala_proxy::tls::UpstreamTls;
use dvarapala_proxy::{ReverseProxy, serve};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use support::{Ca, der, serve_one, tempdir, write};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// HTTPS upstream with a leaf for `names`, answering "secure".
async fn tls_upstream(ca: &Ca, names: &[&str]) -> SocketAddr {
    let (cert, key) = ca.leaf(names);
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

/// Cleartext proxy in front of `upstream`; GET / and return the status.
async fn get_through(upstream: &str, tls: &UpstreamTls) -> StatusCode {
    let p = ReverseProxy::<Incoming>::with_tls(upstream, tls).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (_stop, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(l, p, async {
        let _ = rx.await;
    }));
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let res = client
        .request(
            Request::get(format!("http://{addr}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    if status == StatusCode::OK {
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"secure");
    }
    status
}

#[tokio::test(flavor = "multi_thread")]
async fn https_upstream_with_ca_file() {
    let ca = Ca::new();
    let up = tls_upstream(&ca, &["127.0.0.1"]).await;
    let tls = UpstreamTls {
        ca_file: Some(write(&tempdir(), "ca.pem", &ca.pem)),
        server_name: None,
    };
    assert_eq!(
        get_through(&format!("https://{up}"), &tls).await,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_upstream_is_502() {
    let up = tls_upstream(&Ca::new(), &["127.0.0.1"]).await;
    let status = get_through(&format!("https://{up}"), &UpstreamTls::default()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_name_overrides_the_host() {
    let ca = Ca::new();
    let up = tls_upstream(&ca, &["other.test"]).await;
    let ca_file = Some(write(&tempdir(), "ca.pem", &ca.pem));
    let wrong = UpstreamTls {
        ca_file: ca_file.clone(),
        server_name: None,
    };
    assert_eq!(
        get_through(&format!("https://{up}"), &wrong).await,
        StatusCode::BAD_GATEWAY
    );
    let right = UpstreamTls {
        ca_file,
        server_name: Some("other.test".into()),
    };
    assert_eq!(
        get_through(&format!("https://{up}"), &right).await,
        StatusCode::OK
    );
}

#[test]
fn unreadable_ca_file_is_an_error() {
    let tls = UpstreamTls {
        ca_file: Some(tempdir().join("missing.pem")),
        server_name: None,
    };
    assert!(ReverseProxy::<Incoming>::with_tls("https://127.0.0.1:1", &tls).is_err());
}
