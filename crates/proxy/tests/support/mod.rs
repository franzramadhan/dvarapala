//! Test CA, certificates on disk, TLS clients and a plain upstream.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::ClientConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The name the listener certificates are issued for.
pub const NAME: &str = "dvarapala.test";

pub struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    pub pem: String,
}

impl Ca {
    pub fn new() -> Self {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap();
        Self {
            pem: issuer.pem(),
            issuer,
        }
    }

    /// A leaf for `names` (DNS names or IP addresses): `(cert_pem, key_pem)`.
    pub fn leaf(&self, names: &[&str]) -> (String, String) {
        let p = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

/// A fresh directory under the system temp dir.
pub fn tempdir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "dvarapala-tls-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

pub fn der(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
}

/// Client trusting `ca_pem`, offering `alpn`.
pub fn client_config(ca_pem: &str, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der(ca_pem)).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}

pub async fn connect(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    TlsConnector::from(config)
        .connect(ServerName::try_from(NAME).unwrap(), tcp)
        .await
}

/// One GET over `stream`, HTTP/2 if ALPN chose it: `(version, status, body)`.
pub async fn get(stream: TlsStream<TcpStream>) -> (Version, StatusCode, String) {
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = TokioIo::new(stream);
    let req = Request::get(format!("https://{NAME}/"))
        .header("host", NAME)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = if h2 {
        let (mut tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(conn);
        tx.send_request(req).await.unwrap()
    } else {
        let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        tx.send_request(req).await.unwrap()
    };
    let (version, status) = (res.version(), res.status());
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (version, status, String::from_utf8(body.to_vec()).unwrap())
}

/// Plain HTTP/1.1 upstream answering `body` to everything.
pub async fn upstream(body: &'static str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(serve_one(TokioIo::new(s), body));
        }
    });
    addr
}

pub async fn serve_one<I>(io: TokioIo<I>, body: &'static str)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
            body.as_bytes(),
        ))))
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await;
}
