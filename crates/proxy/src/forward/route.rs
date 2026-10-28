use http::{Method, Uri};

/// The destination allow list, matched on parsed origins (RFC 0007).
#[derive(Debug, Clone)]
pub struct Routes {
    /// `(https, host lowercase, port)`
    origins: Vec<(bool, String, u16)>,
}

impl Routes {
    /// Fails on an origin that is not `http(s)://host[:port]`, or a repeat.
    pub fn new<'a>(origins: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut out = Vec::new();
        for o in origins {
            let bad = || format!("origin {o:?} is not http(s)://host[:port]");
            let uri: Uri = o.parse().map_err(|_| bad())?;
            let key = origin(&uri).ok_or_else(bad)?;
            if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
                return Err(bad());
            }
            if out.contains(&key) {
                return Err(format!("origin {o:?} is listed twice"));
            }
            out.push(key);
        }
        Ok(Self { origins: out })
    }

    /// The index of the origin `uri` targets: absolute form for most
    /// methods, `host:port` for `CONNECT`. Anything else matches nothing.
    pub fn find(&self, method: &Method, uri: &Uri) -> Option<usize> {
        if method == Method::CONNECT {
            let a = uri.authority().filter(|_| uri.scheme().is_none())?;
            if a.as_str().contains('@') {
                return None;
            }
            let (host, port) = (a.host().to_ascii_lowercase(), a.port_u16()?);
            return self
                .origins
                .iter()
                .position(|(_, h, p)| *h == host && *p == port);
        }
        let key = origin(uri)?;
        self.origins.iter().position(|o| *o == key)
    }
}

/// `(https, host, port)` of an absolute `http(s)://` URI without userinfo.
fn origin(uri: &Uri) -> Option<(bool, String, u16)> {
    let https = match uri.scheme_str()? {
        "http" => false,
        "https" => true,
        _ => return None,
    };
    let a = uri.authority()?;
    if a.as_str().contains('@') || a.host().is_empty() {
        return None;
    }
    let port = a.port_u16().unwrap_or(if https { 443 } else { 80 });
    Some((https, a.host().to_ascii_lowercase(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes() -> Routes {
        Routes::new(["https://api.example", "http://192.0.2.1:8080"]).unwrap()
    }

    fn find(method: Method, uri: &str) -> Option<usize> {
        routes().find(&method, &uri.parse().unwrap())
    }

    #[test]
    fn matches_scheme_host_and_port() {
        assert_eq!(find(Method::GET, "https://api.example/v1"), Some(0));
        assert_eq!(find(Method::GET, "https://API.Example:443/"), Some(0));
        assert_eq!(find(Method::POST, "http://192.0.2.1:8080/x?y"), Some(1));
        assert_eq!(find(Method::GET, "http://api.example/"), None);
        assert_eq!(find(Method::GET, "https://api.example:8443/"), None);
        assert_eq!(find(Method::GET, "https://api.example.evil/"), None);
        assert_eq!(find(Method::GET, "https://user@api.example/"), None);
        assert_eq!(find(Method::GET, "/origin-form"), None);
    }

    #[test]
    fn connect_matches_host_and_port() {
        assert_eq!(find(Method::CONNECT, "api.example:443"), Some(0));
        assert_eq!(find(Method::CONNECT, "192.0.2.1:8080"), Some(1));
        assert_eq!(find(Method::CONNECT, "api.example:80"), None);
    }

    #[test]
    fn rejects_bad_origins() {
        for bad in [
            "ftp://x.example",
            "https://x.example/path",
            "https://u@x.example",
            "x.example",
            "",
        ] {
            assert!(Routes::new([bad]).is_err(), "{bad}");
        }
        assert!(Routes::new(["https://x.example", "https://x.example:443"]).is_err());
    }
}
