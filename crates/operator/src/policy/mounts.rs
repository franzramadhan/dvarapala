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
        let sources = [
            x.config_map.is_some(),
            x.secret.is_some(),
            x.persistent_volume_claim.is_some(),
            x.image.is_some(),
        ];
        if sources.iter().filter(|s| **s).count() != 1 {
            return Err(format!(
                "mount name {n:?}: set one of configMap, secret, persistentVolumeClaim and image"
            ));
        }
        if let Some(c) = &x.persistent_volume_claim
            && !(dns(&c.claim_name, true) && c.claim_name.len() <= 253)
        {
            return Err(format!(
                "mount name {n:?}: claimName {:?} is not a valid name",
                c.claim_name
            ));
        }
        if let Some(i) = &x.image {
            let r = &i.reference;
            if r.is_empty() || r.contains(char::is_whitespace) {
                return Err(format!(
                    "mount name {n:?}: image reference {r:?} is not valid"
                ));
            }
            if !images.iter().any(|p| allowed(r, p)) {
                return Err(format!("mount name {n:?}: image not allowed: {r}"));
            }
            if let Some(p) = i
                .pull_policy
                .as_deref()
                .filter(|p| !PULL_POLICIES.contains(p))
            {
                return Err(format!(
                    "mount name {n:?}: pullPolicy {p:?} is not one of {PULL_POLICIES:?}"
                ));
            }
            if !r.contains("@sha256:") {
                warnings.push(format!("mount {n}: image {r} is not pinned by digest"));
            }
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
