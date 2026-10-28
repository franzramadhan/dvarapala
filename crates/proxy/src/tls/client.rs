use std::path::PathBuf;
use std::sync::Arc;

use hyper_rustls::{FixedServerNameResolver, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};

/// How the proxy verifies `https://` upstreams.
#[derive(Debug, Clone, Default)]
pub struct UpstreamTls {
    /// PEM roots instead of the system store.
    pub ca_file: Option<PathBuf>,
    /// Name verified and sent in SNI instead of the upstream host.
    pub server_name: Option<String>,
}

pub(crate) type Connector = HttpsConnector<HttpConnector>;

impl UpstreamTls {
    /// A connector for `http://` and `https://`. Roots are only loaded when
    /// `https` is set, so a cleartext upstream costs no root store.
    pub(crate) fn connector(&self, https: bool) -> Result<Connector, String> {
        let roots = if https {
            self.roots()?
        } else {
            RootCertStore::empty()
        };
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let b = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http();
        let b = match &self.server_name {
            Some(n) => {
                let name = ServerName::try_from(n.clone())
                    .map_err(|_| format!("server_name {n:?} is not a DNS name or IP address"))?;
                b.with_server_name_resolver(FixedServerNameResolver::new(name))
            }
            None => b,
        };
        Ok(b.enable_http1().build())
    }

    fn roots(&self) -> Result<RootCertStore, String> {
        let mut roots = RootCertStore::empty();
        match &self.ca_file {
            Some(p) => {
                let pem = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
                for c in CertificateDer::pem_slice_iter(&pem) {
                    let c = c.map_err(|e| format!("{}: {e}", p.display()))?;
                    roots.add(c).map_err(|e| format!("{}: {e}", p.display()))?;
                }
                if roots.is_empty() {
                    return Err(format!("{}: no certificates", p.display()));
                }
            }
            None => {
                let found = rustls_native_certs::load_native_certs();
                let (added, _) = roots.add_parsable_certificates(found.certs);
                if added == 0 {
                    tracing::warn!("no system root certificates; set upstream_tls.ca_file");
                }
            }
        }
        Ok(roots)
    }
}
