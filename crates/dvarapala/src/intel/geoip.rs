//! `intel.geoip`: each file read at start and on each reload, swapped
//! only when its bytes change (as the model in RFC 0029).

use std::path::{Path, PathBuf};
#[cfg(feature = "geoip")]
use std::sync::Arc;

/// A loaded database and the hash of the bytes it came from.
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "geoip"), allow(dead_code))]
pub struct Geo {
    #[cfg(feature = "geoip")]
    pub db: Arc<dvarapala_l7::GeoIp>,
    pub path: PathBuf,
    /// hex SHA-256 of the file
    pub sha256: String,
}

/// Reads and opens `path`, or returns its copy in `running` when the file
/// holds the same bytes. Errors name the key and the file.
pub fn load(path: &Path, running: &[Geo]) -> Result<Geo, String> {
    let err = |e: &dyn std::fmt::Display| format!("intel.geoip {}: {e}", path.display());
    #[cfg(not(feature = "geoip"))]
    {
        let _ = running;
        Err(err(&"needs a build with the geoip feature"))
    }
    #[cfg(feature = "geoip")]
    {
        let bytes = std::fs::read(path).map_err(|e| err(&e))?;
        let d = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let sha256: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        if let Some(g) = running
            .iter()
            .find(|g| g.path == path && g.sha256 == sha256)
        {
            return Ok(g.clone());
        }
        let db = dvarapala_l7::GeoIp::from_bytes(bytes).map_err(|e| err(&e))?;
        tracing::info!(
            msg = "geoip loaded",
            path = %path.display(),
            sha256 = %sha256,
            r#type = db.kind()
        );
        Ok(Geo {
            db: Arc::new(db),
            path: path.to_path_buf(),
            sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "geoip"))]
    #[test]
    fn needs_the_feature() {
        let e = load(Path::new("geo.mmdb"), &[]).unwrap_err();
        assert!(e.contains("geoip feature"), "{e}");
    }

    #[cfg(feature = "geoip")]
    #[test]
    fn the_same_bytes_keep_the_database() {
        let dir = std::env::temp_dir().join(format!("dvarapala-geoip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("geo.mmdb");
        let net = "198.51.100.0/24".parse().unwrap();
        std::fs::write(&p, dvarapala_l7::test_db(&[(net, "ZZ", 64500)])).unwrap();
        let a = load(&p, &[]).unwrap();
        let b = load(&p, std::slice::from_ref(&a)).unwrap();
        assert!(Arc::ptr_eq(&a.db, &b.db));
        std::fs::write(&p, dvarapala_l7::test_db(&[(net, "XA", 64501)])).unwrap();
        let c = load(&p, std::slice::from_ref(&a)).unwrap();
        assert!(!Arc::ptr_eq(&a.db, &c.db));
        std::fs::write(&p, b"not a database").unwrap();
        assert!(load(&p, &[c]).unwrap_err().contains("intel.geoip"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "geoip")]
    #[test]
    fn a_reload_swaps_only_the_changed_file() {
        use dvarapala_l7::test_db_fields;
        let dir = std::env::temp_dir().join(format!("dvarapala-geoip2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (country, asn) = (dir.join("country.mmdb"), dir.join("asn.mmdb"));
        let net = "198.51.100.0/24".parse().unwrap();
        std::fs::write(&country, test_db_fields(&[(net, Some("ZZ"), None)])).unwrap();
        std::fs::write(&asn, test_db_fields(&[(net, None, Some(64500))])).unwrap();
        let first = [load(&country, &[]).unwrap(), load(&asn, &[]).unwrap()];
        std::fs::write(&asn, test_db_fields(&[(net, None, Some(64501))])).unwrap();
        let second = [load(&country, &first).unwrap(), load(&asn, &first).unwrap()];
        assert!(Arc::ptr_eq(&first[0].db, &second[0].db));
        assert!(!Arc::ptr_eq(&first[1].db, &second[1].db));
        assert_eq!(second[1].path, asn);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
