//! The TLS listener (RFC 0003) and HTTP/3 next to it (RFC 0006) against
//! the running binary.
#![cfg(all(unix, feature = "tls"))]

#[allow(dead_code)]
mod proc;
mod stop;

use std::path::PathBuf;

use proc::{port, serve, temp, wait_port};
use rcgen::{CertificateParams, KeyPair};

/// A self-signed pair for `localhost`, written to temp files.
struct Pair {
    cert: PathBuf,
    key: PathBuf,
}

impl Pair {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let p = Self {
            cert: temp(&format!("{name}-cert.pem")),
            key: temp(&format!("{name}-key.pem")),
        };
        std::fs::write(&p.cert, cert.pem()).unwrap();
        std::fs::write(&p.key, key.serialize_pem()).unwrap();
        p
    }

    fn toml(&self) -> String {
        format!(
            "[tls]\ncert = \"{}\"\nkey = \"{}\"\n",
            self.cert.display(),
            self.key.display()
        )
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cert);
        let _ = std::fs::remove_file(&self.key);
    }
}

fn base(listen: u16, rate_limit: bool) -> String {
    format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         [metrics]\nlisten = \"\"\n[rate_limit]\nenabled = {rate_limit}\n"
    )
}

// RFC 0003: SIGHUP reads the pair again and keeps the old one on error
#[test]
fn hangup_reloads_the_certificate() {
    let pair = Pair::new("tls-hup");
    let listen = port();
    let p = serve("tls-hup", Some(&(base(listen, true) + &pair.toml())), &[]);
    p.logged(&["proxy listening", "tls=true"]);
    wait_port(listen);
    p.signal("HUP");
    p.logged(&["tls reloaded"]);
    std::fs::write(&pair.cert, "not a certificate").unwrap();
    p.signal("HUP");
    p.logged(&["tls reload failed, keeping the old certificate"]);
    // still accepting
    wait_port(listen);
    let (code, log) = p.stop();
    assert_eq!(code, Some(0), "{log}");
}

// RFC 0006: the UDP listener starts with and without the rate limiter,
// in each retry mode
#[cfg(feature = "http3")]
#[test]
fn http3_listens_next_to_tls() {
    let pair = Pair::new("h3");
    for (rate_limit, retry, shown) in [
        (true, "always", "Always"),
        (false, "never", "Never"),
        (true, "under_load", "UnderLoad"),
    ] {
        let listen = port();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let toml = format!(
            "{}{}[quic]\nlisten = \"127.0.0.1:{udp}\"\nretry = \"{retry}\"\n",
            base(listen, rate_limit),
            pair.toml()
        );
        let p = serve("h3", Some(&toml), &[]);
        p.logged(&["http3 listening", &format!("127.0.0.1:{udp}"), shown]);
        p.logged(&["proxy listening", "tls=true"]);
        wait_port(listen);
        let (code, log) = p.stop();
        assert_eq!(code, Some(0), "{log}");
        assert!(log.contains("stopped"), "{log}");
    }
}
