use std::time::SystemTime;

/// `notAfter` of a DER certificate, read with a minimal DER walk. `None`
/// when the bytes are not a certificate this walk understands.
pub fn not_after(_der: &[u8]) -> Option<SystemTime> {
    todo!("rfc 0003")
}
