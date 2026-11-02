//! A `url` feed's refresh task: `https://` only, the body capped at
//! `intel.max_bytes`, 30 s per fetch, never on the request path.

use std::time::Duration;

use dvarapala_l7::FeedList;
use dvarapala_proxy::UpstreamProtocol;
use dvarapala_proxy::tls::{Connector, UpstreamTls};
use http::Request;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::task::AbortHandle;
use tokio::time::MissedTickBehavior;

use super::feeds::{Failed, apply};
use crate::config;

const TIMEOUT: Duration = Duration::from_secs(30);

/// Fetches the feed now, then every `refresh`. A failure keeps the list
/// in force: empty until the first good fetch.
pub fn spawn(f: &config::Feed, url: &str, max_bytes: usize, list: FeedList) -> Option<AbortHandle> {
    let connector = match UpstreamTls::default().connector(true, UpstreamProtocol::Http1) {
        Ok(c) => c,
        Err(e) => {
            let _ = apply(&f.name, &list, Err(Failed::Fetch(e)), f.max_entries);
            return None;
        }
    };
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let (name, url, every, max) = (f.name.clone(), url.to_owned(), f.refresh, f.max_entries);
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let body = fetch(&client, &url, max_bytes).await;
            let _ = apply(&name, &list, body, max);
        }
    });
    Some(task.abort_handle())
}

async fn fetch(
    client: &Client<Connector, Full<Bytes>>,
    url: &str,
    max: usize,
) -> Result<Vec<u8>, Failed> {
    let call = async {
        let req = Request::get(url)
            .body(Full::default())
            .map_err(|e| Failed::Fetch(e.to_string()))?;
        let res = client
            .request(req)
            .await
            .map_err(|e| Failed::Fetch(e.to_string()))?;
        if !res.status().is_success() {
            return Err(Failed::Fetch(format!("answered {}", res.status())));
        }
        Limited::new(res.into_body(), max)
            .collect()
            .await
            .map(|b| b.to_bytes().to_vec())
            .map_err(|e| match e.downcast_ref::<LengthLimitError>() {
                Some(_) => Failed::TooLarge,
                None => Failed::Fetch(e.to_string()),
            })
    };
    tokio::time::timeout(TIMEOUT, call)
        .await
        .unwrap_or_else(|_| Err(Failed::Fetch("timed out after 30s".into())))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dvarapala_engine::PrefixSet;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;

    use super::*;

    /// An HTTPS server for `localhost` on 127.0.0.1: `/feed` answers a
    /// list, `/big` 1 KiB, anything else 404. A client trusting it.
    async fn server() -> (String, Client<Connector, Full<Bytes>>) {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let ca = std::env::temp_dir().join(format!("fetch-ca-{}.pem", std::process::id()));
        std::fs::write(&ca, cert.pem()).unwrap();
        let tls = UpstreamTls {
            ca_file: Some(ca),
            server_name: Some("localhost".into()),
        };
        let client = Client::builder(TokioExecutor::new())
            .build(tls.connector(true, UpstreamProtocol::Http1).unwrap());

        let sc = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let (status, body) = match req.uri().path() {
                        "/feed" => (200, "192.0.2.0/24\n".to_owned()),
                        "/big" => (200, "#".repeat(1024)),
                        _ => (404, String::new()),
                    };
                    let res = http::Response::builder()
                        .status(status)
                        .body(Full::new(Bytes::from(body)));
                    Ok::<_, http::Error>(res.unwrap())
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc),
                );
            }
        });
        (format!("https://127.0.0.1:{}", addr.port()), client)
    }

    #[tokio::test]
    async fn fetches_answers_and_limits() {
        let (base, client) = server().await;
        let body = fetch(&client, &format!("{base}/feed"), 1024).await.unwrap();
        assert_eq!(body, b"192.0.2.0/24\n");
        let e = fetch(&client, &format!("{base}/nope"), 1024).await;
        assert!(matches!(e, Err(Failed::Fetch(m)) if m.contains("404")));
        let e = fetch(&client, &format!("{base}/big"), 100).await;
        assert!(matches!(e, Err(Failed::TooLarge)));
        let e = fetch(&client, "https://127.0.0.1:1/feed", 1024).await;
        assert!(matches!(e, Err(Failed::Fetch(_))));
        let e = fetch(&client, "not a url", 1024).await;
        assert!(matches!(e, Err(Failed::Fetch(_))));
    }

    #[tokio::test]
    async fn a_failed_fetch_keeps_the_list() {
        let f: config::Feed =
            toml::from_str("name = \"f\"\nurl = \"https://127.0.0.1:1/feed\"\naction = \"deny\"\n")
                .unwrap();
        let list = FeedList::new(PrefixSet::default());
        let task = spawn(&f, "https://127.0.0.1:1/feed", 1024, list.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        task.abort();
        assert!(list.get().is_empty());
    }
}
