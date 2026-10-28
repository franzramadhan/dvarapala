//! Operator-supplied certificate and key files: parsing never panics, and
//! the expiry walk survives any DER.
#![no_main]

use dvarapala_proxy::tls::{CertPair, cert_not_after};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&[u8], &[u8])| {
    let (cert, key) = data;
    if let Ok(pair) = CertPair::from_pem(cert, key) {
        let _ = pair.not_after();
    }
    let _ = cert_not_after(cert);
});
