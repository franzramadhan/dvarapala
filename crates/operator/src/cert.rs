//! The webhook's serving certificate: self-signed, kept in a Secret so
//! every replica serves the same one, and its PEM put in the
//! `MutatingWebhookConfiguration` as the CA bundle.

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
    let c = rcgen::generate_simple_self_signed(names.to_vec()).map_err(|e| e.to_string())?;
    Ok(Pem {
        cert: c.cert.pem(),
        key: c.signing_key.serialize_pem(),
    })
}

/// The pair in Secret `name`, created on first start. Replicas racing to
/// create it all end up with the one that won.
pub async fn ensure(
    client: &Client,
    ns: &str,
    name: &str,
    names: &[String],
) -> Result<Pem, String> {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    for _ in 0..3 {
        if let Some(s) = api.get_opt(name).await.map_err(|e| e.to_string())? {
            let data = s.data.unwrap_or_default();
            let field = |k: &str| {
                data.get(k)
                    .map(|b| String::from_utf8_lossy(&b.0).into_owned())
            };
            if let (Some(cert), Some(key)) = (field("tls.crt"), field("tls.key")) {
                return Ok(Pem { cert, key });
            }
            return Err(format!("secret {ns}/{name} has no tls.crt and tls.key"));
        }
        let pem = generate(names)?;
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(name.into()),
                ..ObjectMeta::default()
            },
            type_: Some("kubernetes.io/tls".into()),
            data: Some(BTreeMap::from([
                ("tls.crt".into(), ByteString(pem.cert.clone().into_bytes())),
                ("tls.key".into(), ByteString(pem.key.clone().into_bytes())),
            ])),
            ..Secret::default()
        };
        match api.create(&PostParams::default(), &secret).await {
            Ok(_) => return Ok(pem),
            // another replica created it first: read theirs
            Err(kube::Error::Api(e)) if e.code == 409 => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(format!("secret {ns}/{name}: kept conflicting"))
}

/// Puts `cert` as the CA bundle of every webhook in configuration `name`.
pub async fn trust(client: &Client, name: &str, cert: &str) -> Result<(), String> {
    let api: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let mut c = api.get(name).await.map_err(|e| format!("{name}: {e}"))?;
    let bundle = ByteString(cert.as_bytes().to_vec());
    if c.webhooks
        .iter()
        .flatten()
        .all(|w| w.client_config.ca_bundle.as_ref() == Some(&bundle))
    {
        return Ok(());
    }
    for w in c.webhooks.iter_mut().flatten() {
        w.client_config.ca_bundle = Some(bundle.clone());
    }
    api.replace(name, &PostParams::default(), &c)
        .await
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(())
}

pub fn server_config(pem: &Pem) -> Result<Arc<ServerConfig>, String> {
    let certs = CertificateDer::pem_slice_iter(pem.cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("tls.crt: {e}"))?;
    let key =
        PrivateKeyDer::from_pem_slice(pem.key.as_bytes()).map_err(|e| format!("tls.key: {e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
