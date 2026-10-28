//! RFC 0003: `https://` upstreams.
#![cfg(feature = "tls")]

mod support;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dvarapala_proxy::tls::UpstreamTls;
use dvarapala_proxy::{Http2Limits, ReverseProxy, UpstreamConfig, UpstreamProtocol, serve};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
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
    tls_upstream_alpn(ca, names, &[]).await
}

/// Like [`tls_upstream`], offering `alpn`; `h2` gets HTTP/2 and the
/// answer "secure h2".
async fn tls_upstream_alpn(ca: &Ca, names: &[&str], alpn: &[&[u8]]) -> SocketAddr {
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
    let mut config = config;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(s) = acceptor.accept(s).await else {
                    return;
                };
                if s.get_ref().1.alpn_protocol() == Some(b"h2") {
                    let svc = service_fn(|_req: Request<Incoming>| async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"secure h2",
                        ))))
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                } else {
                    serve_one(TokioIo::new(s), "secure").await;
                }
            });
        }
    });
    addr
}

fn config(tls: &UpstreamTls) -> UpstreamConfig {
    UpstreamConfig {
        tls: tls.clone(),
        ..UpstreamConfig::default()
    }
}

/// Cleartext proxy in front of `upstream`; GET / and return the status.
async fn get_through(upstream: &str, tls: &UpstreamTls) -> StatusCode {
    let (status, body) = get_with(upstream, &config(tls)).await;
    if status == StatusCode::OK {
        assert_eq!(body, "secure");
    }
    status
}

async fn get_with(upstream: &str, config: &UpstreamConfig) -> (StatusCode, String) {
    let p = ReverseProxy::<Incoming>::with_config(upstream, config).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (_stop, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(l, Http2Limits::default(), p, async {
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
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// RFC 0004: `http2` needs ALPN `h2`, `auto` follows ALPN.
#[tokio::test(flavor = "multi_thread")]
async fn http2_and_auto_over_tls() {
    let ca = Ca::new();
    let tls = UpstreamTls {
        ca_file: Some(write(&tempdir(), "ca.pem", &ca.pem)),
        server_name: None,
    };
    let with = |protocol| UpstreamConfig {
        protocol,
        tls: tls.clone(),
        ..UpstreamConfig::default()
    };
    let h2 = tls_upstream_alpn(&ca, &["127.0.0.1"], &[b"h2", b"http/1.1"]).await;
    let h1 = tls_upstream(&ca, &["127.0.0.1"]).await;
    let get = |up: SocketAddr, p| {
        let c = with(p);
        async move { get_with(&format!("https://{up}"), &c).await }
    };
    assert_eq!(
        get(h2, UpstreamProtocol::Http2).await,
        (StatusCode::OK, "secure h2".into())
    );
    assert_eq!(
        get(h2, UpstreamProtocol::Auto).await,
        (StatusCode::OK, "secure h2".into())
    );
    assert_eq!(
        get(h1, UpstreamProtocol::Auto).await,
        (StatusCode::OK, "secure".into())
    );
    assert_eq!(
        get(h1, UpstreamProtocol::Http2).await.0,
        StatusCode::BAD_GATEWAY
    );
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
    assert!(ReverseProxy::<Incoming>::with_config("https://127.0.0.1:1", &config(&tls)).is_err());
}
