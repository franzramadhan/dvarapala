use std::net::IpAddr;

use crate::Cidr;

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

/// A method name for [`Matcher::methods`]: an HTTP token, upper-cased.
pub fn parse_method(s: &str) -> Result<String, String> {
    if is_token(s) {
        Ok(s.to_ascii_uppercase())
    } else {
        Err(format!("method {s:?} is not an HTTP token"))
    }
}

/// RFC 9110 `token`: the characters of a method or a header name.
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// What a request must look like for a route to apply. Every condition
/// set must hold; an empty matcher matches every request.
#[derive(Debug, Clone, Default)]
pub struct Matcher {
    pub host: Option<Host>,
    pub path: Option<PathMatch>,
    /// Upper case, from [`parse_method`]; any method when empty.
    pub methods: Vec<String>,
    /// Networks of the client key (after `trusted_proxies`); any client
    /// when empty. An IPv6 key is its /64, so a longer prefix never matches.
    pub clients: Vec<Cidr>,
}

impl Matcher {
    /// `host` is the request's host without the port or a trailing dot
    /// (see [`strip_port`]), `None` when it has none; `path` is the raw
    /// path without the query.
    pub fn matches(&self, method: &str, host: Option<&[u8]>, path: &str, client: IpAddr) -> bool {
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == method) {
            return false;
        }
        if let Some(p) = &self.path
            && !p.matches(path)
        {
            return false;
        }
        if let Some(h) = &self.host
            && !host.is_some_and(|host| h.matches(host))
        {
            return false;
        }
        self.clients.is_empty() || self.clients.iter().any(|c| c.contains(client))
    }
}

/// A `Host` header value without the port and a trailing dot.
pub fn strip_port(h: &[u8]) -> &[u8] {
    let h = if h.first() == Some(&b'[') {
        h.iter().position(|&b| b == b']').map_or(h, |i| &h[..=i])
    } else {
        h.iter().rposition(|&b| b == b':').map_or(h, |i| &h[..i])
    };
    h.strip_suffix(b".").unwrap_or(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(m: &Matcher, method: &str, path: &str, host: Option<&str>, client: &str) -> bool {
        let host = host.map(|h| strip_port(h.as_bytes()));
        m.matches(method, host, path, client.parse().unwrap())
    }

    fn path(p: &str) -> Matcher {
        Matcher {
            path: Some(PathMatch::parse(p).unwrap()),
            ..Matcher::default()
        }
    }

    // RFC 0013 case 1 (first match is in the callers; here each condition)
    #[test]
    fn exact_and_prefix_paths() {
        let (login, root) = (path("=/login"), path("/"));
        let c = "192.0.2.1";
        assert!(hit(&login, "GET", "/login", None, c));
        assert!(!hit(&login, "GET", "/login/x", None, c));
        assert!(hit(&root, "GET", "/login/x", None, c));
        assert!(hit(&root, "GET", "/a", None, c));
    }

    // RFC 0013 case 2
    #[test]
    fn host_suffix_ignores_port_and_case() {
        let m = Matcher {
            host: Some(Host::parse("*.example.com").unwrap()),
            ..Matcher::default()
        };
        let c = "192.0.2.1";
        assert!(hit(&m, "GET", "/", Some("a.example.com:8443"), c));
        assert!(hit(&m, "GET", "/", Some("A.EXAMPLE.COM"), c));
        assert!(hit(&m, "GET", "/", Some("a.example.com."), c));
        assert!(!hit(&m, "GET", "/", Some("example.com"), c));
        assert!(!hit(&m, "GET", "/", Some("badexample.com"), c));
        assert!(!hit(&m, "GET", "/", None, c));
        let exact = Matcher {
            host: Some(Host::parse("API.example.com").unwrap()),
            ..Matcher::default()
        };
        assert!(hit(&exact, "GET", "/", Some("api.example.com."), c));
        assert!(!hit(&exact, "GET", "/", Some("x.api.example.com"), c));
        assert_eq!(strip_port(b"[2001:db8::1]:443"), b"[2001:db8::1]");
    }

    // RFC 0013 case 3
    #[test]
    fn raw_path_is_not_decoded() {
        let m = path("/admin");
        let c = "192.0.2.1";
        assert!(hit(&m, "GET", "/admin", None, c));
        assert!(!hit(&m, "GET", "/%61dmin", None, c));
        assert!(!hit(&m, "GET", "//admin", None, c));
    }

    // RFC 0013 case 4
    #[test]
    fn methods_and_clients() {
        let m = Matcher {
            methods: vec![parse_method("post").unwrap()],
            clients: vec!["192.0.2.0/24".parse().unwrap()],
            ..Matcher::default()
        };
        assert!(!hit(&m, "GET", "/", None, "192.0.2.9"));
        assert!(!hit(&m, "POST", "/", None, "198.51.100.9"));
        assert!(hit(&m, "POST", "/", None, "192.0.2.9"));
    }

    #[test]
    fn parse_errors() {
        assert!(PathMatch::parse("api").is_err());
        assert!(PathMatch::parse("=api").is_err());
        assert!(Host::parse("*example.com").is_err());
        assert!(Host::parse("*.").is_err());
        assert!(Host::parse("a.example.com:80").is_err());
        assert!(parse_method("GE T").is_err());
        assert!(parse_method("").is_err());
        assert_eq!(
            Host::parse("*.Example.com").unwrap(),
            Host::Suffix(".example.com".into())
        );
    }
}
