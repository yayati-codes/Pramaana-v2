//! Numeric-string decoding and decompression of the Secure QR payload.

use std::io::Read;

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use num_bigint::BigUint;

use crate::Error;

/// Decimal numeric string (as scanned from the QR) → big-endian bytes.
///
/// The first compressed byte is a zlib (0x78) or gzip (0x1f) header, never
/// 0x00, so BigUint's leading-zero stripping cannot lose payload bytes.
pub(crate) fn numeric_to_bytes(qr: &str) -> Result<Vec<u8>, Error> {
    let qr = qr.trim();
    if qr.is_empty() || !qr.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::NotNumeric);
    }
    let n = BigUint::parse_bytes(qr.as_bytes(), 10).ok_or(Error::NotNumeric)?;
    Ok(n.to_bytes_be())
}

/// Tolerant decompression: real UIDAI QRs are gzip-wrapped, the spec is often
/// described as zlib, and some tooling emits raw DEFLATE. Accept all three.
pub(crate) fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    if ZlibDecoder::new(data).read_to_end(&mut out).is_ok() {
        return Ok(out);
    }
    out.clear();
    if GzDecoder::new(data).read_to_end(&mut out).is_ok() {
        return Ok(out);
    }
    out.clear();
    if DeflateDecoder::new(data).read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Ok(out);
    }
    Err(Error::Decompress)
}
