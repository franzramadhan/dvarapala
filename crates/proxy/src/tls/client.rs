use std::path::PathBuf;

/// How the proxy verifies `https://` upstreams.
#[derive(Debug, Clone, Default)]
pub struct UpstreamTls {
    /// PEM roots instead of the system store.
    pub ca_file: Option<PathBuf>,
    /// Name verified and sent in SNI instead of the upstream host.
    pub server_name: Option<String>,
}
