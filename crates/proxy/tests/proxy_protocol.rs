//! RFC 0030 cases 5 and 6: the client a balancer's PROXY protocol header
//! carries reaches the upstream, in cleartext and over TLS.

#[cfg(feature = "tls")]
mod support;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use dvarapala_l4::proxy_protocol::Version;
use dvarapala_l4::{L4Config, Listener, ProxyProtocol};
use dvarapala_proxy::{Http2Limits, ReverseProxy, serve};
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Upstream answering with the `x-forwarded-for` it got.
async fn echo_xff() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let svc = service_fn(|req: Request<Incoming>| async move {
                let xff = req
                    .headers()
                    .get("x-forwarded-for")
                    .map_or(String::new(), |v| v.to_str().unwrap().to_owned());
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(xff))))
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc),
            );
        }
    });
    addr
}

fn l4(version: Version) -> L4Config {
    L4Config {
        proxy_protocol: Some(ProxyProtocol {
            version,
            from: vec!["127.0.0.0/8".parse().unwrap()],
            timeout: Duration::from_secs(5),
        }),
        ..L4Config::default()
    }
}

/// A v2 header for `192.0.2.10:4000` over IPv4.
fn v2_header() -> Vec<u8> {
    let mut h = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c".to_vec();
    h.extend_from_slice(&[192, 0, 2, 10, 198, 51, 100, 1]);
    h.extend_from_slice(&4000u16.to_be_bytes());
    h.extend_from_slice(&443u16.to_be_bytes());
    h
}

/// RFC 0030 case 5
#[tokio::test]
#[ignore = "rfc 0030"]
async fn v2_header_client_reaches_the_upstream() {
    let up = echo_xff().await;
    let p = ReverseProxy::<Incoming>::new(&format!("http://{up}")).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let l = Listener::new(tcp, l4(Version::V2)).unwrap();
    tokio::spawn(serve(l, Http2Limits::default(), p, std::future::pending()));
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&v2_header()).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut res = String::new();
    s.read_to_string(&mut res).await.unwrap();
    assert!(res.starts_with("HTTP/1.1 200"), "{res}");
    assert!(res.ends_with("192.0.2.10"), "{res}");
}

/// RFC 0030 case 6: the header comes before the ClientHello, which the
/// JA4 fingerprint then reads as usual
#[cfg(feature = "tls")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0030"]
async fn header_then_tls_handshake() {
    use dvarapala_proxy::serve_tls;
    use dvarapala_proxy::tls::{Tls, TlsConfig};
    use rustls::pki_types::ServerName;
    use support::{Ca, NAME, client_config, get, tempdir, write};
    use tokio_rustls::TlsConnector;

    let ca = Ca::new();
    let (cert_pem, key_pem) = ca.leaf(&[NAME]);
    let dir = tempdir();
    let tls = Tls::new(TlsConfig {
        cert: write(&dir, "cert.pem", &cert_pem),
        key: write(&dir, "key.pem", &key_pem),
        handshake_timeout: Duration::from_secs(10),
        max_handshakes: 1024,
        fingerprint: true,
    })
    .unwrap();
    let up = echo_xff().await;
    let p = ReverseProxy::<Incoming>::new(&format!("http://{up}")).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let l = Listener::new(tcp, l4(Version::Any)).unwrap();
    tokio::spawn(serve_tls(
        l,
        tls,
        Http2Limits::default(),
        p,
        std::future::pending(),
    ));
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"PROXY TCP4 192.0.2.10 198.51.100.1 4000 443\r\n")
        .await
        .unwrap();
    let stream = TlsConnector::from(client_config(&ca.pem, &[b"http/1.1"]))
        .connect(ServerName::try_from(NAME).unwrap(), tcp)
        .await
        .unwrap();
    let (_, status, body) = get(stream).await;
    assert_eq!(status, 200);
    assert_eq!(body, "192.0.2.10");
}
