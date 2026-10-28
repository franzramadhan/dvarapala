use http::{Method, Uri};

/// The destination allow list, matched on parsed origins (RFC 0007).
#[derive(Debug, Clone)]
pub struct Routes {
    _todo: (),
}

impl Routes {
    /// Fails on an origin that is not `http(s)://host[:port]`, or a repeat.
    pub fn new<'a>(origins: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let _ = origins.into_iter();
        todo!("rfc 0007")
    }

    /// The index of the origin `uri` targets: absolute form for most
    /// methods, `host:port` for `CONNECT`. Anything else matches nothing.
    pub fn find(&self, method: &Method, uri: &Uri) -> Option<usize> {
        let _ = (method, uri);
        todo!("rfc 0007")
    }
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
    #[ignore = "rfc 0007"]
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
    #[ignore = "rfc 0007"]
    fn connect_matches_host_and_port() {
        assert_eq!(find(Method::CONNECT, "api.example:443"), Some(0));
        assert_eq!(find(Method::CONNECT, "192.0.2.1:8080"), Some(1));
        assert_eq!(find(Method::CONNECT, "api.example:80"), None);
    }

    #[test]
    #[ignore = "rfc 0007"]
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
