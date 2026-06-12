//! Synthetic Secure-QR generator so tests never depend on a real Aadhaar.
//!
//! Builds a payload in the exact wire layout `parse_and_verify` expects,
//! signs it with a locally generated RSA-2048 key, zlib-compresses it, and
//! encodes it as the decimal numeric string a QR scanner would produce.
//! Available to other crates via the `test-gen` cargo feature.

use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use num_bigint::BigUint;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

/// All text fields plus the photo for one synthetic QR. Synthetic PII only.
#[derive(Clone)]
pub struct TestQrSpec {
    pub version: String,
    /// 4 digits.
    pub last4: String,
    /// 17 digits (YYYYMMDDHHMMSSfff).
    pub timestamp: String,
    pub name: String,
    pub dob: String,
    pub gender: String,
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
    pub photo_jp2: Vec<u8>,
}

impl Default for TestQrSpec {
    fn default() -> Self {
        Self {
            version: "V2".into(),
            last4: "4242".into(),
            timestamp: "20260612120000123".into(),
            name: "Asha Example".into(),
            dob: "01-01-1990".into(),
            gender: "F".into(),
            care_of: "C/O Example Parent".into(),
            district: "Ludhiana".into(),
            landmark: "Near Clock Tower".into(),
            house: "12-B".into(),
            location: "Model Town".into(),
            pincode: "141002".into(),
            post_office: "Model Town PO".into(),
            state: "Punjab".into(),
            street: "MG Road".into(),
            sub_district: "Ludhiana West".into(),
            vtc: "Ludhiana".into(),
            // Real decodable 64x64 JPEG2000 (JP2 box format, like genuine
            // Aadhaar photos) so downstream crates can exercise JP2 decoding.
            // Codestreams are naturally full of 0xFF marker bytes, which also
            // proves the photo region is exempt from delimiter splitting.
            photo_jp2: include_bytes!("../testdata/synthetic_face.jp2").to_vec(),
        }
    }
}

/// Generate a fresh RSA-2048 keypair (stand-in for the UIDAI key).
pub fn generate_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
    let public = private.to_public_key();
    (private, public)
}

/// Text fields joined with 0xFF, photo, then the 256-byte PKCS#1 v1.5
/// RSA/SHA-256 signature over everything before it.
pub fn build_signed_payload(spec: &TestQrSpec, signing_key: &RsaPrivateKey) -> Vec<u8> {
    let reference_id = format!("{}{}", spec.last4, spec.timestamp);
    let fields: [&str; 16] = [
        &spec.version,
        &reference_id,
        &spec.name,
        &spec.dob,
        &spec.gender,
        &spec.care_of,
        &spec.district,
        &spec.landmark,
        &spec.house,
        &spec.location,
        &spec.pincode,
        &spec.post_office,
        &spec.state,
        &spec.street,
        &spec.sub_district,
        &spec.vtc,
    ];
    let mut message = Vec::new();
    for field in fields {
        message.extend_from_slice(field.as_bytes());
        message.push(0xFF);
    }
    message.extend_from_slice(&spec.photo_jp2);

    let key = SigningKey::<Sha256>::new(signing_key.clone());
    let signature = key.sign(&message);
    message.extend_from_slice(&signature.to_bytes());
    message
}

/// zlib-compress a payload and encode it as the QR's decimal numeric string.
pub fn encode_payload(payload: &[u8]) -> String {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).expect("compress");
    let compressed = encoder.finish().expect("compress");
    BigUint::from_bytes_be(&compressed).to_str_radix(10)
}

/// Full pipeline: spec → signed payload → compressed → numeric string.
pub fn generate_qr(spec: &TestQrSpec, signing_key: &RsaPrivateKey) -> String {
    encode_payload(&build_signed_payload(spec, signing_key))
}
