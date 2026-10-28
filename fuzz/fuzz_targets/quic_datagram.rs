//! RFC 0006 case 16: arbitrary datagrams into a QUIC server endpoint with
//! the listener's settings never panic. The first byte of each chunk picks
//! accept or Retry for a new connection, as the listener's policy does.
#![no_main]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use quinn_proto::{DatagramEvent, Endpoint, EndpointConfig, ServerConfig};

static SERVER: LazyLock<Arc<ServerConfig>> = LazyLock::new(|| {
    let c = rcgen::generate_simple_self_signed(vec!["dvarapala.test".into()]).unwrap();
    let key = rustls_pki_types::PrivatePkcs8KeyDer::from(c.signing_key.serialize_der());
    Arc::new(ServerConfig::with_single_cert(vec![c.cert.der().clone()], key.into()).unwrap())
});

fuzz_target!(|data: &[u8]| {
    let mut e = Endpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(SERVER.clone()),
        true,
        Some([0; 32]),
    );
    let (now, remote): (_, SocketAddr) = (Instant::now(), "192.0.2.1:4433".parse().unwrap());
    let mut conns = HashMap::new();
    let mut buf = Vec::new();
    // chunks of up to 1500 bytes, one per datagram
    for chunk in data.chunks(1500) {
        let Some((&pick, dgram)) = chunk.split_first() else {
            continue;
        };
        match e.handle(now, remote, None, None, BytesMut::from(dgram), &mut buf) {
            Some(DatagramEvent::NewConnection(i)) if pick & 1 == 0 => {
                if let Ok((h, c)) = e.accept(i, now, &mut buf, None) {
                    conns.insert(h, c);
                }
            }
            Some(DatagramEvent::NewConnection(i)) => {
                let _ = e.retry(i, &mut buf);
            }
            Some(DatagramEvent::ConnectionEvent(h, ev)) => {
                if let Some(c) = conns.get_mut(&h) {
                    c.handle_event(ev);
                    while c.poll_transmit(now, 1, &mut buf).is_some() {
                        buf.clear();
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }
});
