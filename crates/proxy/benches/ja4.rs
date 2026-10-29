//! RFC 0012 case 20: CPU per JA4, on a real rustls ClientHello.

use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_proxy::tls::ja4::from_handshake;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// The handshake message of the first flight rustls sends.
fn hello() -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let name = ServerName::try_from("dvarapala.test").unwrap();
    let mut conn = ClientConnection::new(Arc::new(c), name).unwrap();
    let mut wire = Vec::new();
    conn.write_tls(&mut wire).unwrap();
    wire[5..].to_vec()
}

fn bench(c: &mut Criterion) {
    let h = hello();
    assert!(from_handshake(&h).is_some());
    c.bench_function("ja4", |b| {
        b.iter(|| from_handshake(std::hint::black_box(&h)))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
