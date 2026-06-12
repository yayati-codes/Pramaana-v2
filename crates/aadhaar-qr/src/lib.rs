//! Aadhaar Secure QR handling (ARCHITECTURE.md §5).
//!
//! Parse the Secure QR, verify the UIDAI RSA-2048/SHA-256 signature, extract
//! demographic fields + the JPEG2000 photo, and compute the STABLE
//! timestamp-stripped digest (§2 step 6, §4): the 17 timestamp bytes in the
//! referenceId are zeroed before hashing so re-scans are deterministic.
//!
//! Enrollment is signature-verified, never OCR. The wire format mirrors PSE's
//! @anon-aadhaar/core: decimal numeric string → big-endian bytes → DEFLATE
//! decompress → 0xFF-delimited text fields → JPEG2000 photo → trailing
//! 256-byte RSA signature over everything before it.

mod decode;
mod parse;
mod verify;

#[cfg(any(test, feature = "test-gen"))]
pub mod testgen;

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub use rsa::{RsaPrivateKey, RsaPublicKey};

/// Errors from [`parse_and_verify`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("QR content is not a decimal numeric string")]
    NotNumeric,
    #[error("payload does not decompress as zlib, gzip, or raw DEFLATE")]
    Decompress,
    #[error("decompressed payload too short to contain a signature ({len} bytes)")]
    TooShort { len: usize },
    #[error("expected {expected} 0xFF-delimited text fields, found {found}")]
    MissingFields { expected: usize, found: usize },
    #[error("field `{field}` is not valid UTF-8")]
    InvalidUtf8 { field: &'static str },
    #[error("referenceId is malformed (need 4-digit last-4 + 17-digit timestamp)")]
    MalformedReferenceId,
    #[error("UIDAI signature verification failed")]
    SignatureInvalid,
}

/// Address fields in UIDAI Secure QR order.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct Address {
    pub care_of: String,
    pub district: String,
    pub landmark: String,
    pub house: String,
    pub location: String,
    pub pincode: String,
    pub post_office: String,
    pub state: String,
    pub street: String,
    pub sub_district: String,
    pub vtc: String,
}

/// Verified contents of one Secure QR scan.
///
/// Holds PII: zeroized on drop, deliberately neither `Clone` nor a
/// PII-printing `Debug` (CLAUDE.md non-negotiables, §4). `stable_digest` is
/// the only field meant to outlive the enrollment flow.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AadhaarRecord {
    /// Version/indicator field (e.g. "V2").
    pub version: String,
    /// Last 4 digits of the Aadhaar number (from the referenceId).
    pub reference_last4: String,
    /// 17-digit issuance timestamp (from the referenceId). NOT identity material.
    pub timestamp: String,
    pub name: String,
    /// DD-MM-YYYY.
    pub dob: String,
    pub gender: String,
    pub address: Address,
    /// Raw JPEG2000 photo bytes. Liveness input only — never key material (§4).
    pub photo_jp2: Vec<u8>,
    /// SHA-256 over the signed message (payload minus the trailing 256-byte
    /// signature) with the 17 timestamp bytes zeroed. Identical across
    /// re-scans and across QRs differing only in issuance timestamp.
    pub stable_digest: [u8; 32],
}

impl fmt::Debug for AadhaarRecord {
    /// Redacted: never prints demographics or the photo.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut digest_hex = String::with_capacity(64);
        for b in self.stable_digest {
            digest_hex.push_str(&format!("{b:02x}"));
        }
        f.debug_struct("AadhaarRecord")
            .field("version", &self.version)
            .field("reference_last4", &self.reference_last4)
            .field("photo_jp2_len", &self.photo_jp2.len())
            .field("stable_digest", &digest_hex)
            .finish_non_exhaustive()
    }
}

/// Decode a Secure QR numeric string, verify the UIDAI signature, and extract
/// the record. The signature is checked BEFORE any field is interpreted.
pub fn parse_and_verify(
    qr_numeric: &str,
    uidai_pubkey: &RsaPublicKey,
) -> Result<AadhaarRecord, Error> {
    let compressed = decode::numeric_to_bytes(qr_numeric)?;
    let mut payload = decode::decompress(&compressed)?;

    if payload.len() <= parse::SIGNATURE_LEN {
        let len = payload.len();
        payload.zeroize();
        return Err(Error::TooShort { len });
    }
    let (message, signature) = payload.split_at(payload.len() - parse::SIGNATURE_LEN);

    let result = verify::verify_signature(message, signature, uidai_pubkey)
        .and_then(|()| parse::build_record(message));
    payload.zeroize();
    result
}

#[cfg(test)]
mod tests;
