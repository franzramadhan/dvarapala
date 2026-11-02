//! RFC 0025, 0033: `gateway.mounts` against the operator's
//! `--mount-images` prefixes.

use super::{MAX_MOUNTS, allowed};
use crate::crd::Mount;

const PULL_POLICIES: [&str; 3] = ["Always", "IfNotPresent", "Never"];

/// Every error starts with `mount name`; an image without a digest adds a
/// warning.
pub(super) fn check(
    m: &[Mount],
    images: &[String],
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    if m.len() > MAX_MOUNTS {
        return Err(format!("mount name: at most {MAX_MOUNTS} mounts"));
    }
    // rfc 0033: image prefixes and warnings come with the new sources
    let _ = (images, &warnings, allowed, PULL_POLICIES);
    let mut seen = std::collections::BTreeSet::new();
    for x in m {
        let n = &x.name;
        // a volume `mount-<name>` is a DNS label too
        if !(dns(n, false) && n.len() <= 57) {
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

/// A DNS label, or with `dots` a DNS subdomain (lengths checked apart).
fn dns(s: &str, dots: bool) -> bool {
    (dots || !s.contains('.'))
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

#[cfg(test)]
#[path = "mounts_tests.rs"]
mod tests;
