use std::net::IpAddr;

use dvarapala_engine::{Cidr, parse_country};
use maxminddb::Reader;
use serde::Deserialize;

/// A MaxMind DB file (GeoLite2 Country, ASN or City, or a file in the
/// same format), read whole into memory.
#[derive(Debug)]
pub struct GeoIp(Reader<Vec<u8>>);

/// The fields read from a record; the rest is skipped.
#[derive(Deserialize)]
struct Record<'a> {
    #[serde(borrow)]
    country: Option<Country<'a>>,
    autonomous_system_number: Option<u32>,
}

#[derive(Deserialize)]
struct Country<'a> {
    iso_code: Option<&'a str>,
}

impl GeoIp {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        Reader::from_source(bytes)
            .map(Self)
            .map_err(|e| e.to_string())
    }

    /// The database type from its metadata, such as `GeoLite2-Country`.
    pub fn kind(&self) -> &str {
        &self.0.metadata().database_type
    }

    /// An address the database does not hold, or a record without the
    /// fields, has no country and no ASN.
    pub(crate) fn lookup(&self, ip: IpAddr) -> (Option<[u8; 2]>, Option<u32>) {
        let Ok(found) = self.0.lookup(ip.to_canonical()) else {
            return (None, None);
        };
        let Ok(Some(r)) = found.decode::<Record<'_>>() else {
            return (None, None);
        };
        let country = r.country.and_then(|c| c.iso_code);
        let country = country.and_then(|c| parse_country(c).ok());
        (country, r.autonomous_system_number)
    }
}

#[doc(hidden)]
/// Fuzzing entry point: a database from arbitrary bytes, then lookups.
pub fn fuzz_geoip(data: &[u8]) {
    let ips = [
        IpAddr::from([192, 0, 2, 1]),
        IpAddr::from([0, 0, 0, 0]),
        IpAddr::from([255, 255, 255, 255]),
        "2001:db8::1".parse().unwrap(),
    ];
    if let Ok(g) = GeoIp::from_bytes(data.to_vec()) {
        for ip in ips {
            let _ = g.lookup(ip);
        }
    }
    // the first byte splits the rest into two files, looked up together
    if let Some((&at, rest)) = data.split_first() {
        let (a, b) = rest.split_at(usize::from(at).min(rest.len()));
        let geo = [a, b]
            .into_iter()
            .filter_map(|d| GeoIp::from_bytes(d.to_vec()).ok().map(std::sync::Arc::new));
        let intel = crate::Intel::new(Vec::new()).with_geo(geo);
        for ip in ips {
            let _ = intel.check(ip);
        }
    }
}

#[doc(hidden)]
/// A minimal IPv4 MaxMind DB for tests: each network maps to a country
/// code and an ASN. Networks must not overlap; IPv6 ones are skipped.
pub fn test_db(entries: &[(Cidr, &str, u32)]) -> Vec<u8> {
    let entries: Vec<_> = entries
        .iter()
        .map(|&(net, cc, asn)| (net, Some(cc), Some(asn)))
        .collect();
    test_db_fields(&entries)
}

#[doc(hidden)]
/// [`test_db`] with either field left out, like a GeoLite2 Country file
/// (no ASN) or an ASN file (no country).
pub fn test_db_fields(entries: &[(Cidr, Option<&str>, Option<u32>)]) -> Vec<u8> {
    #[derive(Clone, Copy)]
    enum Rec {
        Empty,
        Node(usize),
        Data(usize),
    }
    let mut nodes = vec![[Rec::Empty; 2]];
    let mut data = Vec::new();
    for (net, cc, asn) in entries {
        let IpAddr::V4(a) = net.addr() else { continue };
        let (bits, len) = (u32::from(a), usize::from(net.prefix()));
        let offset = data.len();
        map(
            &mut data,
            usize::from(cc.is_some()) + usize::from(asn.is_some()),
        );
        if let Some(cc) = cc {
            string(&mut data, "country");
            map(&mut data, 1);
            string(&mut data, "iso_code");
            string(&mut data, cc);
        }
        if let Some(asn) = asn {
            string(&mut data, "autonomous_system_number");
            uint(&mut data, 6, u64::from(*asn));
        }
        let mut node = 0;
        for i in 0..len {
            let bit = ((bits >> (31 - i)) & 1) as usize;
            if i + 1 == len {
                nodes[node][bit] = Rec::Data(offset);
            } else if let Rec::Node(n) = nodes[node][bit] {
                node = n;
            } else {
                nodes.push([Rec::Empty; 2]);
                nodes[node][bit] = Rec::Node(nodes.len() - 1);
                node = nodes.len() - 1;
            }
        }
    }
    let count = nodes.len();
    let mut out = Vec::new();
    for rec in nodes.iter().flatten() {
        let v = match *rec {
            Rec::Empty => count,
            Rec::Node(n) => n,
            Rec::Data(off) => count + 16 + off,
        };
        out.extend_from_slice(&(v as u32).to_be_bytes()[1..]);
    }
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
    map(&mut out, 9);
    for (k, v) in [
        ("binary_format_major_version", 2),
        ("binary_format_minor_version", 0),
    ] {
        string(&mut out, k);
        uint(&mut out, 5, v);
    }
    string(&mut out, "build_epoch");
    uint(&mut out, 9, 0);
    string(&mut out, "database_type");
    string(&mut out, "Dvarapala-Test");
    string(&mut out, "description");
    map(&mut out, 1);
    string(&mut out, "en");
    string(&mut out, "test");
    string(&mut out, "ip_version");
    uint(&mut out, 5, 4);
    string(&mut out, "languages");
    control(&mut out, 11, 1);
    string(&mut out, "en");
    string(&mut out, "node_count");
    uint(&mut out, 6, count as u64);
    string(&mut out, "record_size");
    uint(&mut out, 5, 24);
    out
}

/// A field's control byte: the type in the top three bits (types above 7
/// in a second byte) and a size under 29.
fn control(out: &mut Vec<u8>, kind: u8, size: usize) {
    assert!(size < 29, "test_db writes short fields only");
    if kind <= 7 {
        out.push((kind << 5) | size as u8);
    } else {
        out.extend_from_slice(&[size as u8, kind - 7]);
    }
}

fn map(out: &mut Vec<u8>, pairs: usize) {
    control(out, 7, pairs);
}

fn string(out: &mut Vec<u8>, s: &str) {
    control(out, 2, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// An unsigned integer of type `kind` (5, 6 or 9) in its fewest bytes.
fn uint(out: &mut Vec<u8>, kind: u8, v: u64) {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    control(out, kind, 8 - skip);
    out.extend_from_slice(&bytes[skip..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // RFC 0031 case 10, on the reader
    #[test]
    fn a_generated_database_maps_networks_to_country_and_asn() {
        let db = test_db(&[
            ("198.51.100.0/24".parse().unwrap(), "ZZ", 64500),
            ("192.0.2.128/25".parse().unwrap(), "XA", 4_200_000_000),
        ]);
        let g = GeoIp::from_bytes(db).unwrap();
        assert_eq!(g.kind(), "Dvarapala-Test");
        assert_eq!(g.lookup(ip("198.51.100.1")), (Some(*b"ZZ"), Some(64500)));
        assert_eq!(g.lookup(ip("::ffff:198.51.100.9")).1, Some(64500));
        assert_eq!(
            g.lookup(ip("192.0.2.200")),
            (Some(*b"XA"), Some(4_200_000_000))
        );
        assert_eq!(g.lookup(ip("192.0.2.1")), (None, None));
        assert_eq!(g.lookup(ip("203.0.113.1")), (None, None));
        // an IPv4 database has no IPv6 networks
        assert_eq!(g.lookup(ip("2001:db8::1")), (None, None));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(GeoIp::from_bytes(Vec::new()).is_err());
        assert!(GeoIp::from_bytes(b"\xAB\xCD\xEFMaxMind.com".to_vec()).is_err());
        let mut db = test_db(&[("198.51.100.0/24".parse().unwrap(), "ZZ", 64500)]);
        db.truncate(10);
        assert!(GeoIp::from_bytes(db).is_err());
        fuzz_geoip(b"anything");
    }
}
