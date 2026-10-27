use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `notAfter` of a DER certificate, read with a minimal DER walk. `None`
/// when the bytes are not a certificate this walk understands.
pub fn not_after(der: &[u8]) -> Option<SystemTime> {
    let (0x30, cert, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _) = tlv(cert)? else {
        return None;
    };
    // [0] version is optional, then serial, signature and issuer
    let (tag, _, after) = tlv(tbs)?;
    let mut rest = if tag == 0xa0 { after } else { tbs };
    for _ in 0..3 {
        rest = tlv(rest)?.2;
    }
    let (0x30, validity, _) = tlv(rest)? else {
        return None;
    };
    let (tag, time, _) = tlv(tlv(validity)?.2)?;
    parse_time(tag, time)
}

/// One DER element: `(tag, value, rest)`.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, mut b) = b.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |l, &x| l << 8 | usize::from(x));
        b = &b[n..];
        len
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
fn parse_time(tag: u8, t: &[u8]) -> Option<SystemTime> {
    let year_digits = match tag {
        0x17 => 2,
        0x18 => 4,
        _ => return None,
    };
    let (digits, z) = t.split_at_checked(t.len().checked_sub(1)?)?;
    if z != b"Z" || digits.len() != year_digits + 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| {
        digits[r]
            .iter()
            .fold(0i64, |n, &d| n * 10 + i64::from(d - b'0'))
    };
    let mut year = num(0..year_digits);
    if tag == 0x17 {
        // RFC 5280 4.1.2.5.1
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let at = |i| num(year_digits + i..year_digits + i + 2);
    let (month, day, hour, min, sec) = (at(0), at(2), at(4), at(6), at(8));
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).ok()?))
}

/// Days since 1970-01-01 (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(tag: u8, t: &str) -> Option<u64> {
        parse_time(tag, t.as_bytes()).map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs())
    }

    #[test]
    fn utc_and_generalized_time() {
        assert_eq!(secs(0x17, "700101000000Z"), Some(0));
        assert_eq!(secs(0x17, "310102000000Z"), Some(1_925_078_400));
        assert_eq!(secs(0x18, "20310102000000Z"), Some(1_925_078_400));
        // leap day, and a year past 2049 needs GeneralizedTime
        assert_eq!(secs(0x18, "20240229120000Z"), Some(1_709_208_000));
        assert_eq!(secs(0x18, "20510101000000Z"), Some(2_556_144_000));
    }

    #[test]
    fn malformed_times_are_none() {
        for (tag, t) in [
            (0x17, ""),
            (0x17, "Z"),
            (0x17, "3101020000Z"),
            (0x17, "310102000000"),
            (0x17, "3101020000+0Z"),
            (0x17, "311302000000Z"),
            (0x18, "310102000000Z"),
            (0x04, "310102000000Z"),
            // before the epoch
            (0x17, "690101000000Z"),
        ] {
            assert_eq!(secs(tag, t), None, "{t:?}");
        }
    }

    #[test]
    fn truncated_der_is_none() {
        assert_eq!(not_after(&[]), None);
        assert_eq!(not_after(&[0x30, 0x82, 0xff]), None);
        assert_eq!(not_after(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), None);
        assert_eq!(not_after(&[0x30, 0x02, 0x30, 0x00]), None);
    }
}
