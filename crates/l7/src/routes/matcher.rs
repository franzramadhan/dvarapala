use std::net::IpAddr;

use dvarapala_engine::Cidr;
use http::header::HOST;
use http::{HeaderMap, Method, Uri};

/// A route's host condition, compared without the port and ignoring case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// `api.example.com`
    Exact(String),
    /// `*.example.com`, kept as `.example.com`: any name under it, not the
    /// name itself.
    Suffix(String),
}

impl Host {
    /// `"*.example.com"` is a suffix, anything else an exact name.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim_end_matches('.').to_ascii_lowercase();
        if s.is_empty() || s.contains(['/', ':', ' ']) {
            return Err(format!(
                "host {s:?}: a name like \"api.example.com\" or \"*.example.com\""
            ));
        }
        match s.strip_prefix('*') {
            Some(rest) if rest.starts_with('.') && rest.len() > 1 => Ok(Self::Suffix(rest.into())),
            Some(_) => Err(format!("host {s:?}: a wildcard is only \"*.<name>\"")),
            None => Ok(Self::Exact(s)),
        }
    }

    fn matches(&self, host: &[u8]) -> bool {
        match self {
            Self::Exact(h) => host.eq_ignore_ascii_case(h.as_bytes()),
            Self::Suffix(s) => {
                host.len() > s.len()
                    && host[host.len() - s.len()..].eq_ignore_ascii_case(s.as_bytes())
            }
        }
    }
}

/// A route's path condition, on the raw path: no decoding, no
/// normalization, so the route sees the string the upstream serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatch {
    /// `/api/`
    Prefix(String),
    /// `=/login`
    Exact(String),
}

impl PathMatch {
    /// A prefix, or an exact path with a leading `=`; either starts with `/`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (exact, p) = match s.strip_prefix('=') {
            Some(p) => (true, p),
            None => (false, s),
        };
        if !p.starts_with('/') {
            return Err(format!(
                "path {s:?}: must start with \"/\" (or \"=/\" for an exact path)"
            ));
        }
        Ok(if exact {
            Self::Exact(p.into())
        } else {
            Self::Prefix(p.into())
        })
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Prefix(p) => path.starts_with(p.as_str()),
            Self::Exact(p) => path == p,
        }
    }
}

/// What a request must look like for a route to apply. Every condition
/// set must hold; an empty matcher matches every request.
#[derive(Debug, Clone, Default)]
pub struct Matcher {
    pub host: Option<Host>,
    pub path: Option<PathMatch>,
    /// Any method when empty.
    pub methods: Vec<Method>,
    /// Networks of the client key (after `trusted_proxies`); any client
    /// when empty. An IPv6 key is its /64, so a longer prefix never matches.
    pub clients: Vec<Cidr>,
}

impl Matcher {
    pub fn matches(&self, uri: &Uri, headers: &HeaderMap, method: &Method, client: IpAddr) -> bool {
        if !self.methods.is_empty() && !self.methods.contains(method) {
            return false;
        }
        if let Some(p) = &self.path
            && !p.matches(uri.path())
        {
            return false;
        }
        if let Some(h) = &self.host
            && !host_of(uri, headers).is_some_and(|host| h.matches(host))
        {
            return false;
        }
        self.clients.is_empty() || self.clients.iter().any(|c| c.contains(client))
    }
}

/// The request's host without the port or a trailing dot: the URI's
/// authority (HTTP/2, absolute form), else the `Host` header.
fn host_of<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> Option<&'a [u8]> {
    let raw = match uri.host() {
        Some(h) => h.as_bytes(),
        None => strip_port(headers.get(HOST)?.as_bytes()),
    };
    Some(raw.strip_suffix(b".").unwrap_or(raw))
}

fn strip_port(h: &[u8]) -> &[u8] {
    if h.first() == Some(&b'[') {
        return h.iter().position(|&b| b == b']').map_or(h, |i| &h[..=i]);
    }
    h.iter().rposition(|&b| b == b':').map_or(h, |i| &h[..i])
}

#[cfg(test)]
mod tests {
    use http::Request;

    use super::*;

    fn req(method: &str, uri: &str, host: Option<&str>) -> Request<()> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(h) = host {
            b = b.header(HOST, h);
        }
        b.body(()).unwrap()
    }

    fn hit(m: &Matcher, r: &Request<()>, client: &str) -> bool {
        m.matches(r.uri(), r.headers(), r.method(), client.parse().unwrap())
    }

    fn path(p: &str) -> Matcher {
        Matcher {
            path: Some(PathMatch::parse(p).unwrap()),
            ..Matcher::default()
        }
    }

    // RFC 0013 case 1 (first match is in `Routes`; here each condition)
    #[test]
    fn exact_and_prefix_paths() {
        let login = path("=/login");
        let root = path("/");
        let c = "192.0.2.1";
        assert!(hit(&login, &req("GET", "/login", None), c));
        assert!(!hit(&login, &req("GET", "/login/x", None), c));
        assert!(hit(&root, &req("GET", "/login/x", None), c));
        assert!(hit(&root, &req("GET", "/a", None), c));
    }

    // RFC 0013 case 2
    #[test]
    fn host_suffix_ignores_port_and_case() {
        let m = Matcher {
            host: Some(Host::parse("*.example.com").unwrap()),
            ..Matcher::default()
        };
        let c = "192.0.2.1";
        assert!(hit(&m, &req("GET", "/", Some("a.example.com:8443")), c));
        assert!(hit(&m, &req("GET", "/", Some("A.EXAMPLE.COM")), c));
        assert!(hit(&m, &req("GET", "https://a.example.com./x", None), c));
        assert!(!hit(&m, &req("GET", "/", Some("example.com")), c));
        assert!(!hit(&m, &req("GET", "/", Some("badexample.com")), c));
        assert!(!hit(&m, &req("GET", "/", None), c));
        let exact = Matcher {
            host: Some(Host::parse("API.example.com").unwrap()),
            ..Matcher::default()
        };
        assert!(hit(&exact, &req("GET", "/", Some("api.example.com.")), c));
        assert!(!hit(&exact, &req("GET", "/", Some("x.api.example.com")), c));
    }

    // RFC 0013 case 3
    #[test]
    fn raw_path_is_not_decoded() {
        let m = path("/admin");
        let c = "192.0.2.1";
        assert!(hit(&m, &req("GET", "/admin", None), c));
        assert!(!hit(&m, &req("GET", "/%61dmin", None), c));
        assert!(!hit(&m, &req("GET", "//admin", None), c));
    }

    // RFC 0013 case 4
    #[test]
    fn methods_and_clients() {
        let m = Matcher {
            methods: vec![Method::POST],
            clients: vec!["192.0.2.0/24".parse().unwrap()],
            ..Matcher::default()
        };
        assert!(!hit(&m, &req("GET", "/", None), "192.0.2.9"));
        assert!(!hit(&m, &req("POST", "/", None), "198.51.100.9"));
        assert!(hit(&m, &req("POST", "/", None), "192.0.2.9"));
    }

    #[test]
    fn parse_errors() {
        assert!(PathMatch::parse("api").is_err());
        assert!(PathMatch::parse("=api").is_err());
        assert!(Host::parse("*example.com").is_err());
        assert!(Host::parse("*.").is_err());
        assert!(Host::parse("a.example.com:80").is_err());
        assert_eq!(
            Host::parse("*.Example.com").unwrap(),
            Host::Suffix(".example.com".into())
        );
    }
}
