//! A policy's TOML: the keys the operator owns, the rendered file, and
//! the hash that changes only when a key needs a restart.

use toml::{Table, Value};

use crate::crd::PolicySpec;
use crate::gateway::{APP, GATEWAY, MANAGED_BY, RESTART_HASH};

/// Keys the operator sets per gateway; a policy may not.
pub const OWNED: &[&str] = &[
    "mode",
    "listen",
    "upstream",
    "upstream_protocol",
    "pool",
    "config_watch",
    "metrics.listen",
    "admin.listen",
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
    // RFC 0029
    "ml.model",
    "ml.threshold",
];

/// RFC 0025: at most this many `gateway.mounts`.
pub const MAX_MOUNTS: usize = 16;

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

/// RFC 0025: [`render`], then the `gateway` fields against the config and
/// the operator's `--waf-images` prefixes. `Ok` carries the warnings:
/// accepted, but probably not meant.
pub fn check(spec: &PolicySpec, waf_images: &[String]) -> Result<(Rendered, Vec<String>), String> {
    let r = render(&spec.config)?;
    let table: Table = r.toml.parse().map_err(|e: toml::de::Error| e.to_string())?;
    let g = &spec.gateway;
    let mut warnings = Vec::new();
    if g.admin.as_ref().is_some_and(|a| a.enabled) {
        if spec.secret_ref.is_none() {
            return Err("admin needs secretRef".into());
        }
    } else if get(&table, "admin").is_some() {
        // the gateway would refuse to start without admin.listen
        return Err("config: [admin] needs gateway.admin".into());
    }
    if let Some(w) = &g.waf {
        if get(&table, "waf.endpoint").is_some() {
            return Err("config: waf.endpoint is set by the operator with gateway.waf".into());
        }
        if !waf_images.iter().any(|p| allowed(&w.image, p)) {
            return Err(format!("waf image not allowed: {}", w.image));
        }
        if w.config_map.is_empty() {
            return Err("gateway.waf.configMap is empty".into());
        }
        if !w.image.contains("@sha256:") {
            warnings.push(format!("waf image {} is not pinned by digest", w.image));
        }
        if get(&table, "waf.enabled").and_then(Value::as_bool) != Some(true) {
            warnings.push("gateway.waf without [waf] enabled = true: an idle sidecar".into());
        }
    }
    mounts(spec)?;
    let reserved = [APP.0, MANAGED_BY.0, GATEWAY];
    if let Some(k) = g.pod_labels.keys().find(|k| reserved.contains(&k.as_str())) {
        return Err(format!("reserved pod label: {k}"));
    }
    if g.pod_annotations.contains_key(RESTART_HASH) {
        return Err(format!("reserved pod annotation: {RESTART_HASH}"));
    }
    Ok((r, warnings))
}

/// `image` starts with `prefix` at a name boundary: a prefix of
/// `.../coraza-spoa` allows `.../coraza-spoa:<tag>`, not
/// `.../coraza-spoa-other`.
fn allowed(image: &str, prefix: &str) -> bool {
    !prefix.is_empty()
        && image.strip_prefix(prefix).is_some_and(|rest| {
            prefix.ends_with('/') || rest.is_empty() || rest.starts_with([':', '@'])
        })
}

fn mounts(spec: &PolicySpec) -> Result<(), String> {
    let m = &spec.gateway.mounts;
    if m.len() > MAX_MOUNTS {
        return Err(format!("mount name: at most {MAX_MOUNTS} mounts"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for x in m {
        let n = &x.name;
        // a volume `mount-<name>` is a DNS label too
        let label = !n.is_empty()
            && n.len() <= 57
            && n.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !n.starts_with('-')
            && !n.ends_with('-');
        if !label {
            return Err(format!(
                "mount name {n:?}: not a DNS label of at most 57 characters"
            ));
        }
        if !seen.insert(n) {
            return Err(format!("mount name {n:?}: used twice"));
        }
        if x.config_map.is_some() == x.secret.is_some() {
            return Err(format!("mount name {n:?}: set one of configMap and secret"));
        }
    }
    Ok(())
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

    fn spec(config: &str) -> PolicySpec {
        PolicySpec {
            config: config.into(),
            ..PolicySpec::default()
        }
    }

    fn images() -> Vec<String> {
        vec!["ghcr.io/corazawaf/coraza-spoa".into()]
    }

    fn with_admin(mut p: PolicySpec, secret: bool) -> PolicySpec {
        p.gateway.admin = Some(crate::crd::Admin { enabled: true });
        p.secret_ref = secret.then(|| crate::crd::SecretRef { name: "s".into() });
        p
    }

    fn with_waf(mut p: PolicySpec, image: &str) -> PolicySpec {
        p.gateway.waf = Some(crate::crd::Waf {
            image: image.into(),
            config_map: "coraza".into(),
            resources: None,
        });
        p
    }

    // RFC 0025 case 3
    #[test]
    fn admin_needs_a_secret_ref() {
        let e = check(&with_admin(spec(""), false), &images()).unwrap_err();
        assert_eq!(e, "admin needs secretRef");
        assert!(check(&with_admin(spec(""), true), &images()).is_ok());
    }

    // RFC 0025 case 4
    #[test]
    fn admin_keys_but_listen_are_the_policys() {
        let ui = "[admin]\nui_enabled = true\n";
        assert!(check(&with_admin(spec(ui), true), &images()).is_ok());
        let e = check(
            &with_admin(spec("[admin]\nlisten = \"0.0.0.0:1\"\n"), true),
            &images(),
        )
        .unwrap_err();
        assert!(e.contains("admin.listen"), "{e}");
        // without gateway.admin the gateway would not start
        let e = check(&spec(ui), &images()).unwrap_err();
        assert!(e.contains("gateway.admin"), "{e}");
    }

    // RFC 0025 case 6
    #[test]
    fn waf_images_outside_the_allowlist_are_refused() {
        let on = "[waf]\nenabled = true\n";
        for bad in [
            "docker.io/evil/agent",
            "ghcr.io/corazawaf/coraza-spoa-evil:1",
            "ghcr.io/corazawaf",
        ] {
            let e = check(&with_waf(spec(on), bad), &images()).unwrap_err();
            assert!(e.starts_with("waf image not allowed"), "{bad}: {e}");
        }
        let pinned = "ghcr.io/corazawaf/coraza-spoa:0.9.1@sha256:00";
        let (_, w) = check(&with_waf(spec(on), pinned), &images()).unwrap();
        assert!(w.is_empty(), "{w:?}");
        let (_, w) = check(
            &with_waf(spec(""), "ghcr.io/corazawaf/coraza-spoa"),
            &images(),
        )
        .unwrap();
        assert_eq!(w.len(), 2, "unpinned and idle: {w:?}");
        // an empty allowlist refuses every sidecar
        assert!(check(&with_waf(spec(on), pinned), &[]).is_err());
    }

    // RFC 0025 case 7
    #[test]
    fn waf_endpoint_is_owned_with_the_sidecar() {
        let c = "[waf]\nenabled = true\nendpoint = \"127.0.0.1:1\"\n";
        assert!(check(&spec(c), &images()).is_ok());
        let pinned = "ghcr.io/corazawaf/coraza-spoa@sha256:00";
        let e = check(&with_waf(spec(c), pinned), &images()).unwrap_err();
        assert!(e.contains("waf.endpoint"), "{e}");
    }

    // RFC 0025 case 9
    #[test]
    fn bad_mounts_are_named() {
        let m = |name: &str| crate::crd::Mount {
            name: name.into(),
            config_map: Some("c".into()),
            secret: None,
        };
        let mut p = spec("");
        for (mounts, want) in [
            (vec![m("../x")], "\"../x\""),
            (vec![m("a"), m("a")], "used twice"),
            ((0..17).map(|i| m(&format!("m{i}"))).collect(), "at most 16"),
            (
                vec![crate::crd::Mount {
                    secret: Some("s".into()),
                    ..m("both")
                }],
                "one of",
            ),
        ] {
            p.gateway.mounts = mounts;
            let e = check(&p, &images()).unwrap_err();
            assert!(e.starts_with("mount name") && e.contains(want), "{e}");
        }
        p.gateway.mounts = vec![m("pg-ca"), m("llm-key")];
        assert!(check(&p, &images()).is_ok());
    }

    // RFC 0025 case 10
    #[test]
    fn operator_pod_labels_are_reserved() {
        let mut p = spec("");
        p.gateway.pod_labels = [("app.kubernetes.io/name".into(), "x".into())].into();
        assert_eq!(
            check(&p, &images()).unwrap_err(),
            "reserved pod label: app.kubernetes.io/name"
        );
        p.gateway.pod_labels = [("team".into(), "shop".into())].into();
        assert!(check(&p, &images()).is_ok());
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

    // RFC 0029 case 12
    #[test]
    fn model_and_threshold_keep_the_restart_hash() {
        let a = render("[ml]\nmodel = \"/m/a.json\"\nthreshold = 0.9\n").unwrap();
        let b = render("[ml]\nmodel = \"/m/b.json\"\nthreshold = 0.5\n").unwrap();
        let llm = render("[ml.llm]\nmodel = \"x\"\n").unwrap();
        assert_ne!(a.hash, b.hash);
        assert_eq!(a.restart_hash, b.restart_hash);
        assert_eq!(a.restart_hash, render("").unwrap().restart_hash);
        assert_ne!(llm.restart_hash, a.restart_hash);
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
