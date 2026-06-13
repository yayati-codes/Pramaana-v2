use std::sync::{Arc, OnceLock};

use aadhaar_qr::testgen::{self, TestQrSpec};
use aadhaar_qr::{RsaPrivateKey, RsaPublicKey};
use attestation::sim::SimVerifier;
use attestation::{verify_report_data_binding, Verifier};
use liveness::{decode_jp2, CaptureMetadata, ChallengeNonce, LiveCapture, SimMatcher};
use voprf_vault::http::VaultServer;
use voprf_vault::VoprfVault;

use crate::registry::InMemoryRegistry;
use crate::{AttestationMode, EnrollError, EnrollmentRequest, EnrollmentTee, HttpVaultClient};

fn uidai_keys() -> &'static (RsaPrivateKey, RsaPublicKey) {
    static KEYS: OnceLock<(RsaPrivateKey, RsaPublicKey)> = OnceLock::new();
    KEYS.get_or_init(testgen::generate_keypair)
}

/// One vault server shared by all tests (its key is fixed by seed anyway).
fn vault_url() -> &'static str {
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        let vault = Arc::new(
            VoprfVault::from_seed(
                b"sim-sealed-seed-tee",
                b"pramaana-vault-v1",
                SimVerifier::default(),
            )
            .unwrap(),
        );
        let (addr, _handle) = VaultServer::spawn(vault, "127.0.0.1:0").unwrap();
        format!("http://{addr}")
    })
}

fn make_tee() -> EnrollmentTee<SimMatcher, InMemoryRegistry> {
    EnrollmentTee::new(
        AttestationMode::from_env().unwrap(),
        uidai_keys().1.clone(),
        HttpVaultClient::connect(vault_url()).unwrap(),
        InMemoryRegistry::default(),
        SimMatcher::default(),
    )
}

const LIVENESS_NONCE: ChallengeNonce = ChallengeNonce([0x0C; 32]);

/// A "live capture" whose face is the QR photo itself (same person).
fn matching_capture(spec: &TestQrSpec) -> LiveCapture {
    let face = decode_jp2(&spec.photo_jp2).unwrap();
    LiveCapture {
        frames: vec![face.clone(), face],
        metadata: CaptureMetadata {
            nonce_echo: LIVENESS_NONCE.0,
            captured_at_ms: 1_781_000_000_000,
        },
    }
}

fn request_for(spec: &TestQrSpec) -> EnrollmentRequest {
    EnrollmentRequest {
        qr_numeric: testgen::generate_qr(spec, &uidai_keys().0),
        live_capture: matching_capture(spec),
        liveness_nonce: LIVENESS_NONCE,
    }
}

#[test]
fn gate0_handshake_verifies() {
    let tee = make_tee();
    let client_nonce = b"client-gate0-nonce";
    let handshake = tee.gate0_handshake(client_nonce).unwrap();

    // C's side: appraisal policy + report_data binding, then (and only
    // then) proceed.
    let verified = SimVerifier::default().verify(&handshake.quote).unwrap();
    verify_report_data_binding(&verified, client_nonce, &handshake.ephemeral_pubkey).unwrap();
}

#[test]
fn enroll_happy_path() {
    let tee = make_tee();
    let out = tee.enroll(request_for(&TestQrSpec::default())).unwrap();

    assert!(!out.handle.already_enrolled);
    assert!(out.handle.phi.iter().any(|&b| b != 0));
    // §3: C receives sk_IdR (ML-KEM-1024 dk) over the attested channel.
    assert_eq!(out.sk_idr.len(), 3168);
    assert_eq!(tee.registry().identity_count(), 1);
}

#[test]
fn rescan_reproduces_phi_and_dedup_blocks() {
    let tee = make_tee();
    let spec = TestQrSpec::default();

    let first = tee.enroll(request_for(&spec)).unwrap();
    assert!(!first.handle.already_enrolled);

    // DoD: same QR re-enrolled → SAME Φ (recovery-by-rescan), dedup blocks
    // a second mint — and the SAME sk_IdR is re-derived for C.
    let again = tee.enroll(request_for(&spec)).unwrap();
    assert_eq!(again.handle.phi, first.handle.phi);
    assert!(again.handle.already_enrolled);
    assert_eq!(*again.sk_idr, *first.sk_idr);
    assert_eq!(tee.registry().identity_count(), 1);

    // Re-issued QR (same person, fresh issuance timestamp) → same identity.
    let mut reissued = spec.clone();
    reissued.timestamp = "20270301080000777".into();
    let third = tee.enroll(request_for(&reissued)).unwrap();
    assert_eq!(third.handle.phi, first.handle.phi);
    assert!(third.handle.already_enrolled);
    assert_eq!(tee.registry().identity_count(), 1);

    // A different person enrolls fine.
    let mut other = spec.clone();
    other.last4 = "7777".into();
    other.name = "Birbal Example".into();
    let fourth = tee.enroll(request_for(&other)).unwrap();
    assert_ne!(fourth.handle.phi, first.handle.phi);
    assert!(!fourth.handle.already_enrolled);
    assert_eq!(tee.registry().identity_count(), 2);
}

#[test]
fn pii_erased_after_enroll() {
    let tee = make_tee();
    let mut observed = false;
    let out = tee
        .enroll_inner(request_for(&TestQrSpec::default()), |scratch| {
            assert!(
                scratch.is_wiped(),
                "QR numeric + stable_id must be wiped before enroll returns"
            );
            observed = true;
        })
        .unwrap();
    assert!(observed);
    // The handle itself carries public data only: Φ and the dedup tag are
    // both derived through the issuer-unknown k (and are what goes on-chain
    // anyway); already_enrolled is a bool. No demographic field exists on
    // the type — compile-level guarantee. sk_IdR rides separately on the
    // output (Zeroizing) and is NOT part of the handle.
    let handle = out.handle;
    let _: ([u8; 64], [u8; 32], bool) = (handle.phi, handle.dedup_tag, handle.already_enrolled);
}

#[test]
fn rejections() {
    let tee = make_tee();
    let spec = TestQrSpec::default();

    // Tampered QR: flip a payload byte, re-encode. Fails at §2 step 5,
    // before any vault interaction (registry stays empty).
    let mut payload = testgen::build_signed_payload(&spec, &uidai_keys().0);
    payload[20] ^= 0x01;
    let request = EnrollmentRequest {
        qr_numeric: testgen::encode_payload(&payload),
        live_capture: matching_capture(&spec),
        liveness_nonce: LIVENESS_NONCE,
    };
    assert!(matches!(
        tee.enroll(request).unwrap_err(),
        EnrollError::Qr(aadhaar_qr::Error::SignatureInvalid)
    ));
    assert_eq!(tee.registry().identity_count(), 0);

    // Live face that is not the QR person (flat stripes pattern).
    let mut bad_face = matching_capture(&spec);
    let stripes = {
        let mut rgb = Vec::with_capacity(64 * 64 * 3);
        for _y in 0..64u32 {
            for x in 0..64u32 {
                let v = if (x / 8) % 2 == 0 { 230 } else { 25 };
                rgb.extend_from_slice(&[v, v, v]);
            }
        }
        liveness::Image::new(64, 64, rgb).unwrap()
    };
    bad_face.frames = vec![stripes.clone(), stripes];
    let request = EnrollmentRequest {
        qr_numeric: testgen::generate_qr(&spec, &uidai_keys().0),
        live_capture: bad_face,
        liveness_nonce: LIVENESS_NONCE,
    };
    assert!(matches!(
        tee.enroll(request).unwrap_err(),
        EnrollError::FaceMismatch { .. }
    ));

    // Wrong liveness nonce echo (replayed capture).
    let mut replayed = matching_capture(&spec);
    replayed.metadata.nonce_echo = [0xFF; 32];
    let request = EnrollmentRequest {
        qr_numeric: testgen::generate_qr(&spec, &uidai_keys().0),
        live_capture: replayed,
        liveness_nonce: LIVENESS_NONCE,
    };
    assert!(matches!(
        tee.enroll(request).unwrap_err(),
        EnrollError::Liveness(liveness::Error::NonceMismatch)
    ));

    assert_eq!(tee.registry().identity_count(), 0);
}
