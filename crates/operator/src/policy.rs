//! A policy's TOML: the keys the operator owns, the rendered file, and
//! the hash that changes only when a key needs a restart.

use toml::{Table, Value};

/// Keys the operator sets per gateway; a policy may not.
pub const OWNED: &[&str] = &[
    "mode",
    "listen",
    "upstream",
    "upstream_protocol",
    "pool",
    "config_watch",
    "metrics.listen",
    "admin",
    "xdp",
    "quic",
    "tls",
];

/// RFC 0014: the keys a reload applies in place.
pub const RELOADABLE: &[&str] = &[
    "trusted_proxies",
    "rate_limit.rate",
    "rate_limit.burst",
    "detection.mode",
    "detection.attack_rate_factor",
    "challenge",
    "fingerprint",
    "routes",
    "waf",
];

/// The file the gateways mount.
pub const FILE: &str = "dvarapala.toml";

#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    /// Canonical TOML: sorted keys, no comments.
    pub toml: String,
    /// Of the whole file.
    pub hash: String,
    /// Of the keys that need a restart: put in the pod template, so the
    /// gateway rolls only for those.
    pub restart_hash: String,
}

/// Parses `config`, refuses the operator's keys.
pub fn render(config: &str) -> Result<Rendered, String> {
    let table: Table = config
        .parse()
        .map_err(|e: toml::de::Error| format!("config: {}", e.message()))?;
    if let Some(k) = OWNED.iter().find(|k| get(&table, k).is_some()) {
        return Err(format!("config: {k} is set by the operator"));
    }
    let toml = table.to_string();
    Ok(Rendered {
        hash: hash(&toml),
        restart_hash: hash(&fixed(&table).to_string()),
        toml,
    })
}

/// The ConfigMap of the policy named `policy`.
pub fn config_map_name(policy: &str) -> String {
    format!("dvarapala-{policy}")
}

/// `table` without the keys a reload applies, and without empty tables
/// left behind.
fn fixed(table: &Table) -> Table {
    // RFC 0014: with a shared store the cluster budget is set at start
    let shared = get(table, "store.backend")
        .and_then(Value::as_str)
        .is_some_and(|b| b != "memory");
    let mut t = table.clone();
    for k in RELOADABLE {
        if !(shared && k.starts_with("rate_limit.")) {
            remove(&mut t, k);
        }
    }
    t.retain(|_, v| !matches!(v, Value::Table(t) if t.is_empty()));
    t
}

fn get<'a>(t: &'a Table, path: &str) -> Option<&'a Value> {
    let (head, rest) = path.split_once('.').unwrap_or((path, ""));
    let v = t.get(head)?;
    if rest.is_empty() {
        return Some(v);
    }
    get(v.as_table()?, rest)
}

fn remove(t: &mut Table, path: &str) {
    match path.split_once('.') {
        None => drop(t.remove(path)),
        Some((head, rest)) => {
            if let Some(Value::Table(inner)) = t.get_mut(head) {
                remove(inner, rest);
            }
        }
    }
}

/// Hex of the first 8 bytes of the SHA-256.
pub fn hash(s: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
    d.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // case 9
    #[test]
    fn owned_keys_and_bad_toml_refused() {
        let e = render("listen = \"0.0.0.0:1\"").unwrap_err();
        assert!(e.contains("listen"), "{e}");
        let e = render("[admin]\nlisten = \"127.0.0.1:9091\"").unwrap_err();
        assert!(e.contains("admin"), "{e}");
        let e = render("[metrics]\nlisten = \"0.0.0.0:1\"").unwrap_err();
        assert!(e.contains("metrics.listen"), "{e}");
        assert!(
            render("[rate_limit\nrate = 1")
                .unwrap_err()
                .starts_with("config: ")
        );
        // metrics keys other than listen are the policy's
        assert!(render("[metrics]").is_ok());
    }

    // case 11
    #[test]
    fn whitespace_and_comments_do_not_change_the_hash() {
        let a = render("[rate_limit]\nrate = 5\nburst = 9\n").unwrap();
        let b = render("# tuned\n[rate_limit]\n  burst   = 9 # max\n\n  rate = 5\n").unwrap();
        assert_eq!(a, b);
    }

    // case 10
    #[test]
    fn reloadable_keys_keep_the_restart_hash() {
        let base = render("[rate_limit]\nrate = 5\n[l4]\nmax_connections = 10\n").unwrap();
        let rate = render("[rate_limit]\nrate = 1\n[l4]\nmax_connections = 10\n").unwrap();
        let l4 = render("[rate_limit]\nrate = 5\n[l4]\nmax_connections = 20\n").unwrap();
        assert_ne!(base.hash, rate.hash);
        assert_eq!(base.restart_hash, rate.restart_hash);
        assert_ne!(base.restart_hash, l4.restart_hash);
        // a section only holding reloadable keys, present or not
        let mode = render("[detection]\nmode = \"enforce\"\n").unwrap();
        assert_eq!(mode.restart_hash, render("").unwrap().restart_hash);
        // a shared store: the rate needs a restart
        let store = "[store]\nbackend = \"redis\"\n[rate_limit]\nrate = ";
        let s1 = render(&format!("{store}5\n")).unwrap();
        let s2 = render(&format!("{store}1\n")).unwrap();
        assert_ne!(s1.restart_hash, s2.restart_hash);
    }

    // case 10: the list agrees with the binary's
    #[test]
    fn reloadable_list_matches_the_binary() {
        let src = include_str!("../../dvarapala/src/reload.rs");
        let body = src
            .split_once("pub fn restart(")
            .and_then(|(_, b)| b.split_once("\n}\n"))
            .map_or("", |(b, _)| b);
        let restart: Vec<&str> = body
            .split("(\"")
            .skip(1)
            .filter_map(|s| s.split_once('"').map(|(k, _)| k))
            .collect();
        assert!(
            restart.contains(&"listen") && restart.contains(&"l4"),
            "{restart:?}"
        );
        for k in RELOADABLE {
            assert!(!restart.contains(k), "{k} needs a restart in reload.rs");
        }
        for k in [
            "trusted_proxies",
            "rate_limit.rate",
            "attack_rate_factor",
            "challenge",
            "fingerprint",
            "routes",
            "waf",
        ] {
            assert!(
                src.contains(k.rsplit('.').next().unwrap()),
                "{k} not in reload.rs"
            );
        }
    }
}
