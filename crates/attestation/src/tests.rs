use sha2::{Digest, Sha256, Sha512};

use crate::sim::{SimAttester, SimVerifier, SIM_MEASUREMENT};
use crate::{
    bind_report_data, quoted_report_data, verify_report_data_binding, Attester, Error, Verifier,
    MEASUREMENT_LEN, REPORT_DATA_LEN,
};

const NONCE: &[u8] = b"gate-challenge-nonce-32-bytes-ok";
const TLS_PUBKEY: &[u8] = &[0xA1; 32]; // Gate 0: ephemeral TLS pubkey
const BLINDED: &[u8] = &[0xB2; 32]; // Gate b: blinded VOPRF input

#[test]
fn sim_quote_round_trip() {
    let report_data = bind_report_data(NONCE, TLS_PUBKEY);
    let quote = SimAttester::default().quote(&report_data).unwrap();

    let verified = SimVerifier::default().verify(&quote).unwrap();
    assert_eq!(verified.measurement, SIM_MEASUREMENT);
    assert_eq!(verified.backend, "sim");
    assert_eq!(
        verified.stored_report_data,
        quoted_report_data(&report_data)
    );

    // The shared gate check: correct (nonce, value) binds.
    verify_report_data_binding(&verified, NONCE, TLS_PUBKEY).unwrap();
}

#[test]
fn tampered_report_data_fails() {
    let report_data = bind_report_data(NONCE, TLS_PUBKEY);
    let mut quote = SimAttester::default().quote(&report_data).unwrap();

    // Flip one byte of the stored report_data region.
    let last = quote.len() - 1;
    quote[last] ^= 0x01;
    let verified = SimVerifier::default().verify(&quote).unwrap();
    assert_eq!(
        verify_report_data_binding(&verified, NONCE, TLS_PUBKEY).unwrap_err(),
        Error::BindingMismatch
    );

    // Binding to the WRONG value (e.g. attacker swapped the TLS key) fails
    // even with an untampered quote.
    let honest = SimVerifier::default()
        .verify(&SimAttester::default().quote(&report_data).unwrap())
        .unwrap();
    assert_eq!(
        verify_report_data_binding(&honest, NONCE, &[0xEE; 32]).unwrap_err(),
        Error::BindingMismatch
    );
    // Replayed quote under a fresh nonce fails (anti-replay).
    assert_eq!(
        verify_report_data_binding(&honest, b"fresh-nonce", TLS_PUBKEY).unwrap_err(),
        Error::BindingMismatch
    );
}

#[test]
fn unknown_measurement_and_malformed_quotes_fail() {
    let report_data = bind_report_data(NONCE, TLS_PUBKEY);
    let rogue = SimAttester {
        measurement: [0x66; MEASUREMENT_LEN],
    };
    assert_eq!(
        SimVerifier::default()
            .verify(&rogue.quote(&report_data).unwrap())
            .unwrap_err(),
        Error::MeasurementRejected
    );

    assert!(matches!(
        SimVerifier::default().verify(b"short").unwrap_err(),
        Error::Malformed(_)
    ));
    let mut bad_magic = SimAttester::default().quote(&report_data).unwrap();
    bad_magic[0] = b'X';
    assert!(matches!(
        SimVerifier::default().verify(&bad_magic).unwrap_err(),
        Error::Malformed(_)
    ));
}

#[test]
fn binding_helper_gate0_and_gateb() {
    // Deterministic for both gate usages.
    let gate0 = bind_report_data(NONCE, TLS_PUBKEY);
    let gate_b = bind_report_data(NONCE, BLINDED);
    assert_eq!(gate0, bind_report_data(NONCE, TLS_PUBKEY));
    assert_eq!(gate_b, bind_report_data(NONCE, BLINDED));

    // Different value / different nonce / swapped roles → different binding.
    assert_ne!(gate0, gate_b);
    assert_ne!(gate0, bind_report_data(b"other-nonce", TLS_PUBKEY));
    assert_ne!(gate0, bind_report_data(TLS_PUBKEY, NONCE));

    // Length framing: ("ab", "c") and ("a", "bc") must differ.
    assert_ne!(bind_report_data(b"ab", b"c"), bind_report_data(b"a", b"bc"));

    // The helper is exactly SHA-512(domain || len(nonce) || nonce || value).
    let mut h = Sha512::new();
    h.update(b"pramaana-report-data-v1");
    h.update((NONCE.len() as u64).to_le_bytes());
    h.update(NONCE);
    h.update(TLS_PUBKEY);
    assert_eq!(gate0.0, <[u8; 64]>::from(h.finalize()));
}

#[test]
fn sha256_wrapping_convention() {
    // dstack/TDX quotes store sha256(report_data) zero-padded, not the raw
    // 64 bytes. The wrapper must be exactly that...
    let report_data = bind_report_data(NONCE, BLINDED);
    let stored = quoted_report_data(&report_data);
    assert_eq!(stored.len(), REPORT_DATA_LEN);
    assert_eq!(stored[..32], Sha256::digest(report_data.0)[..]);
    assert_eq!(stored[32..], [0u8; 32]);

    // ...and what the attester actually puts in the quote (Gate b shape).
    let quote = SimAttester::default().quote(&report_data).unwrap();
    let verified = SimVerifier::default().verify(&quote).unwrap();
    assert_eq!(verified.stored_report_data, stored);
    verify_report_data_binding(&verified, NONCE, BLINDED).unwrap();
}
