use crate::crd::{ClaimMount, ImageMount, Mount, PolicySpec};
use crate::policy::check;

const GEO: &str = "registry.example/geo/";
const PINNED: &str = "registry.example/geo/lite:1@sha256:00";

fn cm(name: &str) -> Mount {
    Mount {
        name: name.into(),
        config_map: Some("c".into()),
        ..Mount::default()
    }
}

fn pvc(name: &str, claim: &str) -> Mount {
    Mount {
        name: name.into(),
        persistent_volume_claim: Some(ClaimMount {
            claim_name: claim.into(),
        }),
        ..Mount::default()
    }
}

fn image(name: &str, reference: &str) -> Mount {
    Mount {
        name: name.into(),
        image: Some(ImageMount {
            reference: reference.into(),
            pull_policy: None,
        }),
        ..Mount::default()
    }
}

fn with(mounts: Vec<Mount>, images: &[&str]) -> Result<Vec<String>, String> {
    let mut p = PolicySpec::default();
    p.gateway.mounts = mounts;
    let images: Vec<String> = images.iter().map(|s| (*s).to_owned()).collect();
    check(&p, &[], &images).map(|(_, w)| w)
}

// RFC 0025 case 9
#[test]
fn bad_mounts_are_named() {
    for (mounts, want) in [
        (vec![cm("../x")], "\"../x\""),
        (vec![cm("a.b")], "\"a.b\""),
        (vec![cm("a"), cm("a")], "used twice"),
        (
            (0..17).map(|i| cm(&format!("m{i}"))).collect(),
            "at most 16",
        ),
        (
            vec![Mount {
                secret: Some("s".into()),
                ..cm("both")
            }],
            "one of",
        ),
    ] {
        let e = with(mounts, &[]).unwrap_err();
        assert!(e.starts_with("mount name") && e.contains(want), "{e}");
    }
    assert_eq!(with(vec![cm("pg-ca"), cm("llm-key")], &[]), Ok(vec![]));
}

// RFC 0033 case 3, and case 2's no warning
#[test]
#[ignore = "rfc 0033"]
fn an_image_without_a_digest_is_a_warning() {
    assert_eq!(with(vec![image("geoip", PINNED)], &[GEO]), Ok(vec![]));
    let w = with(vec![image("geoip", "registry.example/geo/lite:1")], &[GEO]).unwrap();
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].contains("geoip") && w[0].contains("digest"), "{w:?}");
}

// RFC 0033 case 4
#[test]
#[ignore = "rfc 0033"]
fn images_outside_mount_images_are_refused() {
    for (reference, images) in [
        (PINNED, &[][..]),
        ("docker.io/evil/geo@sha256:00", &[GEO][..]),
        (
            "registry.example/geography@sha256:00",
            &["registry.example/geo"][..],
        ),
    ] {
        let e = with(vec![image("geoip", reference)], images).unwrap_err();
        assert!(
            e.starts_with("mount name \"geoip\": image not allowed"),
            "{e}"
        );
    }
    let mut m = image("geoip", PINNED);
    m.image.as_mut().unwrap().pull_policy = Some("Sometimes".into());
    let e = with(vec![m.clone()], &[GEO]).unwrap_err();
    assert!(e.contains("pullPolicy"), "{e}");
    m.image.as_mut().unwrap().pull_policy = Some("Always".into());
    assert!(with(vec![m], &[GEO]).is_ok());
}

// RFC 0033 case 5
#[test]
#[ignore = "rfc 0033"]
fn a_mount_needs_exactly_one_source() {
    let both = Mount {
        config_map: Some("c".into()),
        ..pvc("geoip", "geo")
    };
    let all = Mount {
        image: Some(ImageMount {
            reference: PINNED.into(),
            pull_policy: None,
        }),
        ..both.clone()
    };
    let none = Mount {
        name: "geoip".into(),
        ..Mount::default()
    };
    for m in [both, all, none] {
        let e = with(vec![m], &[GEO]).unwrap_err();
        assert!(e.starts_with("mount name \"geoip\": set one of"), "{e}");
    }
    for bad in ["", "Geo", "geo_db", "-geo", "geo/x"] {
        let e = with(vec![pvc("geoip", bad)], &[]).unwrap_err();
        assert!(e.contains("claimName"), "{bad}: {e}");
    }
    assert!(with(vec![pvc("geoip", "geo.lite-2")], &[]).is_ok());
}

// RFC 0033 case 6
#[test]
#[ignore = "rfc 0033"]
fn seventeen_mixed_mounts_are_refused() {
    let mixed = |i: usize| match i % 3 {
        0 => cm(&format!("m{i}")),
        1 => pvc(&format!("m{i}"), "geo"),
        _ => image(&format!("m{i}"), PINNED),
    };
    let e = with((0..17).map(mixed).collect(), &[GEO]).unwrap_err();
    assert!(e.contains("at most 16"), "{e}");
    assert!(with((0..16).map(mixed).collect(), &[GEO]).is_ok());
}
