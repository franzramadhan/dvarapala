//! The webhook's serving certificate: self-signed, kept in a Secret so
//! every replica serves the same one, and its PEM put in the
//! `MutatingWebhookConfiguration` as the CA bundle.
#![allow(unused_variables, unused_imports, dead_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use k8s_openapi::ByteString;
use k8s_openapi::api::admissionregistration::v1::MutatingWebhookConfiguration;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Clone, PartialEq)]
pub struct Pem {
    pub cert: String,
    pub key: String,
}

/// A self-signed pair for `names` (DNS SANs).
pub fn generate(names: &[String]) -> Result<Pem, String> {
    todo!("rfc 0019")
}

/// The pair in Secret `name`, created on first start. Replicas racing to
/// create it all end up with the one that won.
pub async fn ensure(
    client: &Client,
    ns: &str,
    name: &str,
    names: &[String],
) -> Result<Pem, String> {
    todo!("rfc 0019")
}

/// Puts `cert` as the CA bundle of every webhook in configuration `name`.
pub async fn trust(client: &Client, name: &str, cert: &str) -> Result<(), String> {
    todo!("rfc 0019")
}

pub fn server_config(pem: &Pem) -> Result<Arc<ServerConfig>, String> {
    todo!("rfc 0019")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "rfc 0019"]
    fn generated_pair_serves_tls() {
        let pem = generate(&["dvarapala-operator.dvarapala.svc".into()]).unwrap();
        assert!(pem.cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(server_config(&pem).is_ok());
        let bad = Pem {
            key: "x".into(),
            ..pem
        };
        assert!(server_config(&bad).is_err());
    }
}
