//! Field-layout parsing and stable-digest computation.
//!
//! Layout (mirrors @anon-aadhaar/core): 16 text fields, each terminated by
//! 0xFF, then the JPEG2000 photo running to the end of the signed message.
//! 0xFF never occurs inside valid UTF-8, so text fields cannot collide with
//! the delimiter; the photo may contain 0xFF freely since splitting stops
//! after the 16th delimiter.

use core::ops::Range;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{AadhaarRecord, Address, Error};

pub(crate) const SIGNATURE_LEN: usize = 256;
pub(crate) const TEXT_FIELD_COUNT: usize = 16;
pub(crate) const LAST4_LEN: usize = 4;
pub(crate) const TIMESTAMP_LEN: usize = 17;

/// Field order: version, referenceId, name, DOB, gender, then the 11 address
/// fields in UIDAI order.
const FIELD_NAMES: [&str; TEXT_FIELD_COUNT] = [
    "version",
    "referenceId",
    "name",
    "dob",
    "gender",
    "careOf",
    "district",
    "landmark",
    "house",
    "location",
    "pincode",
    "postOffice",
    "state",
    "street",
    "subDistrict",
    "vtc",
];

struct SplitMessage<'a> {
    text_fields: Vec<&'a [u8]>,
    photo: &'a [u8],
    /// Byte range of the referenceId field within `message`.
    reference_id: Range<usize>,
}

fn split_message(message: &[u8]) -> Result<SplitMessage<'_>, Error> {
    let mut text_fields = Vec::with_capacity(TEXT_FIELD_COUNT);
    let mut ranges = Vec::with_capacity(TEXT_FIELD_COUNT);
    let mut start = 0usize;
    for _ in 0..TEXT_FIELD_COUNT {
        let rel = message[start..]
            .iter()
            .position(|&b| b == 0xFF)
            .ok_or(Error::MissingFields {
                expected: TEXT_FIELD_COUNT,
                found: text_fields.len(),
            })?;
        text_fields.push(&message[start..start + rel]);
        ranges.push(start..start + rel);
        start += rel + 1;
    }
    Ok(SplitMessage {
        text_fields,
        photo: &message[start..],
        reference_id: ranges[1].clone(),
    })
}

/// SHA-256 over `message` with the 17 timestamp bytes of the referenceId
/// zeroed (§4: re-scans and re-issues hash identically). `message` excludes
/// the trailing signature — the signature covers the timestamp, so including
/// it would break determinism across re-issued QRs.
fn stable_digest(message: &[u8], reference_id: &Range<usize>) -> [u8; 32] {
    let ts_start = reference_id.start + LAST4_LEN;
    let mut copy = message.to_vec();
    copy[ts_start..ts_start + TIMESTAMP_LEN].fill(0);
    let digest = Sha256::digest(&copy).into();
    copy.zeroize();
    digest
}

fn utf8_field(raw: &[u8], index: usize) -> Result<String, Error> {
    core::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| Error::InvalidUtf8 {
            field: FIELD_NAMES[index],
        })
}

/// Parse a signature-verified message into an [`AadhaarRecord`].
pub(crate) fn build_record(message: &[u8]) -> Result<AadhaarRecord, Error> {
    let split = split_message(message)?;

    let reference_id = split.text_fields[1];
    if reference_id.len() < LAST4_LEN + TIMESTAMP_LEN
        || !reference_id[..LAST4_LEN + TIMESTAMP_LEN]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(Error::MalformedReferenceId);
    }

    let mut fields = Vec::with_capacity(TEXT_FIELD_COUNT);
    for (index, raw) in split.text_fields.iter().enumerate() {
        fields.push(utf8_field(raw, index)?);
    }
    let mut fields = fields.into_iter();
    // Order must match FIELD_NAMES.
    let version = fields.next().unwrap();
    let reference = fields.next().unwrap();
    let name = fields.next().unwrap();
    let dob = fields.next().unwrap();
    let gender = fields.next().unwrap();
    let address = Address {
        care_of: fields.next().unwrap(),
        district: fields.next().unwrap(),
        landmark: fields.next().unwrap(),
        house: fields.next().unwrap(),
        location: fields.next().unwrap(),
        pincode: fields.next().unwrap(),
        post_office: fields.next().unwrap(),
        state: fields.next().unwrap(),
        street: fields.next().unwrap(),
        sub_district: fields.next().unwrap(),
        vtc: fields.next().unwrap(),
    };

    // referenceId = last-4 (4) + timestamp (17); validated ASCII digits above,
    // so byte indexing is char-safe.
    let reference_last4 = reference[..LAST4_LEN].to_owned();
    let timestamp = reference[LAST4_LEN..LAST4_LEN + TIMESTAMP_LEN].to_owned();
    let mut reference = reference;
    reference.zeroize();

    Ok(AadhaarRecord {
        version,
        reference_last4,
        timestamp,
        name,
        dob,
        gender,
        address,
        photo_jp2: split.photo.to_vec(),
        stable_digest: stable_digest(message, &split.reference_id),
    })
}
