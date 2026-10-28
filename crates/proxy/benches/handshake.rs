//! RFC 0003 case 19: CPU per full TLS handshake, in memory (no sockets).

use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

fn configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["dvarapala.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // every iteration is a full handshake
    client.resumption = rustls::client::Resumption::disabled();
    (Arc::new(server), Arc::new(client))
}

fn handshake(server: &Arc<ServerConfig>, client: &Arc<ClientConfig>) {
    let name = ServerName::try_from("dvarapala.test").unwrap();
    let mut c = ClientConnection::new(client.clone(), name).unwrap();
    let mut s = ServerConnection::new(server.clone()).unwrap();
    let mut buf = Vec::new();
    while c.is_handshaking() || s.is_handshaking() {
        buf.clear();
        c.write_tls(&mut buf).unwrap();
        s.read_tls(&mut &buf[..]).unwrap();
        s.process_new_packets().unwrap();
        buf.clear();
        s.write_tls(&mut buf).unwrap();
        c.read_tls(&mut &buf[..]).unwrap();
        c.process_new_packets().unwrap();
    }
}

fn bench(c: &mut Criterion) {
    let (server, client) = configs();
    c.bench_function("tls_full_handshake", |b| {
        b.iter(|| handshake(&server, &client))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
