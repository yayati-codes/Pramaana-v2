use std::sync::OnceLock;

use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::testgen::{self, TestQrSpec};
use crate::{decode, parse_and_verify, Error};

/// RSA-2048 keygen is expensive; share one "UIDAI" keypair across tests.
fn uidai_keys() -> &'static (RsaPrivateKey, RsaPublicKey) {
    static KEYS: OnceLock<(RsaPrivateKey, RsaPublicKey)> = OnceLock::new();
    KEYS.get_or_init(testgen::generate_keypair)
}

fn other_keys() -> &'static (RsaPrivateKey, RsaPublicKey) {
    static KEYS: OnceLock<(RsaPrivateKey, RsaPublicKey)> = OnceLock::new();
    KEYS.get_or_init(testgen::generate_keypair)
}

#[test]
fn round_trip() {
    let (sk, pk) = uidai_keys();
    let spec = TestQrSpec::default();
    let qr = testgen::generate_qr(&spec, sk);

    let record = parse_and_verify(&qr, pk).expect("genuine QR must verify");

    assert_eq!(record.version, spec.version);
    assert_eq!(record.reference_last4, spec.last4);
    assert_eq!(record.timestamp, spec.timestamp);
    assert_eq!(record.name, spec.name);
    assert_eq!(record.dob, spec.dob);
    assert_eq!(record.gender, spec.gender);
    assert_eq!(record.address.care_of, spec.care_of);
    assert_eq!(record.address.district, spec.district);
    assert_eq!(record.address.landmark, spec.landmark);
    assert_eq!(record.address.house, spec.house);
    assert_eq!(record.address.location, spec.location);
    assert_eq!(record.address.pincode, spec.pincode);
    assert_eq!(record.address.post_office, spec.post_office);
    assert_eq!(record.address.state, spec.state);
    assert_eq!(record.address.street, spec.street);
    assert_eq!(record.address.sub_district, spec.sub_district);
    assert_eq!(record.address.vtc, spec.vtc);
    assert_eq!(record.photo_jp2, spec.photo_jp2);
}

#[test]
fn tampered_byte_fails_signature() {
    let (sk, pk) = uidai_keys();
    let mut payload = testgen::build_signed_payload(&TestQrSpec::default(), sk);

    // Flip one bit inside the text region (well before the trailing
    // signature). Verification runs before field parsing, so this must
    // surface as SignatureInvalid even if it mangles the field structure.
    payload[10] ^= 0x01;
    let qr = testgen::encode_payload(&payload);

    assert!(matches!(
        parse_and_verify(&qr, pk),
        Err(Error::SignatureInvalid)
    ));
}

#[test]
fn wrong_key_fails_signature() {
    let (sk, _) = uidai_keys();
    let (_, wrong_pk) = other_keys();
    let qr = testgen::generate_qr(&TestQrSpec::default(), sk);

    assert!(matches!(
        parse_and_verify(&qr, wrong_pk),
        Err(Error::SignatureInvalid)
    ));
}

#[test]
fn stable_digest_ignores_timestamp() {
    let (sk, pk) = uidai_keys();
    let spec_a = TestQrSpec::default();
    let mut spec_b = spec_a.clone();
    spec_b.timestamp = "20270101090909999".into();

    let qr_a = testgen::generate_qr(&spec_a, sk);
    let qr_b = testgen::generate_qr(&spec_b, sk);

    // The signatures (and thus the QRs) differ — the timestamp is signed —
    // yet the stable digest must not see it.
    assert_ne!(qr_a, qr_b);
    let sig_a = signature_bytes(&qr_a);
    let sig_b = signature_bytes(&qr_b);
    assert_ne!(sig_a, sig_b);

    let rec_a = parse_and_verify(&qr_a, pk).unwrap();
    let rec_b = parse_and_verify(&qr_b, pk).unwrap();
    assert_eq!(rec_a.stable_digest, rec_b.stable_digest);
}

#[test]
fn stable_digest_is_not_just_last4() {
    let (sk, pk) = uidai_keys();
    let spec = TestQrSpec::default();

    // Same last-4, different name → must be a DIFFERENT person/digest.
    let mut same_last4 = spec.clone();
    same_last4.name = "Birbal Example".into();
    // Different last-4, everything else identical → also a different digest.
    let mut diff_last4 = spec.clone();
    diff_last4.last4 = "7777".into();

    let digest = |s: &TestQrSpec| {
        parse_and_verify(&testgen::generate_qr(s, sk), pk)
            .unwrap()
            .stable_digest
    };
    let base = digest(&spec);
    assert_ne!(base, digest(&same_last4));
    assert_ne!(base, digest(&diff_last4));
}

#[test]
fn malformed_inputs_yield_typed_errors() {
    let (_, pk) = uidai_keys();

    assert!(matches!(
        parse_and_verify("not-a-number", pk),
        Err(Error::NotNumeric)
    ));
    assert!(matches!(parse_and_verify("", pk), Err(Error::NotNumeric)));
    // Valid number, but the bytes are not a DEFLATE stream.
    assert!(matches!(
        parse_and_verify("123456789", pk),
        Err(Error::Decompress)
    ));
    // Decompresses fine but is too short to hold a 256-byte signature.
    let tiny = testgen::encode_payload(&[1, 2, 3]);
    assert!(matches!(
        parse_and_verify(&tiny, pk),
        Err(Error::TooShort { len: 3 })
    ));
}

/// Extract the trailing 256 signature bytes from an encoded QR.
fn signature_bytes(qr: &str) -> Vec<u8> {
    let payload = decode::decompress(&decode::numeric_to_bytes(qr).unwrap()).unwrap();
    payload[payload.len() - 256..].to_vec()
}
