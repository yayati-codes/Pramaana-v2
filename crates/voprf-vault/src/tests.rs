use attestation::sim::{SimAttester, SimVerifier};
use attestation::{bind_report_data, Attester, MEASUREMENT_LEN};

use crate::{VaultError, VoprfVault};

const SEED: &[u8] = b"sim-sealed-vault-seed-0001";
const INFO: &[u8] = b"pramaana-vault-v1";
const STABLE_ID: &[u8] = b"4242|Asha Example|01-01-1990|F|141002";

fn vault() -> VoprfVault<SimVerifier> {
    VoprfVault::from_seed(SEED, INFO, SimVerifier::default()).unwrap()
}

/// T's side of Gate b: blind, get a challenge, quote bound to the blinded
/// input, evaluate, then Gate k: verify the DLEQ proof and unblind.
fn full_protocol_run(vault: &VoprfVault<SimVerifier>) -> voprf::OprfOutput {
    let (state, blinded) = voprf::blind(STABLE_ID).unwrap();
    let nonce = vault.challenge();
    let report_data = bind_report_data(&nonce, &blinded.0);
    let quote = SimAttester::default().quote(&report_data).unwrap();

    let response = vault.evaluate(&nonce, &blinded.0, &quote).unwrap();
    voprf::unblind(
        state,
        STABLE_ID,
        &response.evaluation,
        &response.proof,
        &vault.public_key(),
    )
    .expect("the vault's DLEQ proof must verify client-side")
}

#[test]
fn end_to_end_dleq_verifies() {
    let vault = vault();
    // DoD: the voprf client crate verifies the vault's proof end-to-end —
    // and two independent runs (fresh blinds, fresh nonces) agree on PRF(k, x).
    let out1 = full_protocol_run(&vault);
    let out2 = full_protocol_run(&vault);
    assert_eq!(out1.as_bytes(), out2.as_bytes());
}

#[test]
fn refuses_missing_or_invalid_quote() {
    let vault = vault();
    let (_state, blinded) = voprf::blind(STABLE_ID).unwrap();

    // Missing quote (empty bytes).
    let nonce = vault.challenge();
    assert!(matches!(
        vault.evaluate(&nonce, &blinded.0, &[]).unwrap_err(),
        VaultError::QuoteInvalid(_)
    ));
    // The failed attempt burned the nonce (no retry-grinding).
    let report_data = bind_report_data(&nonce, &blinded.0);
    let good_quote = SimAttester::default().quote(&report_data).unwrap();
    assert_eq!(
        vault.evaluate(&nonce, &blinded.0, &good_quote).unwrap_err(),
        VaultError::UnknownNonce
    );

    // Garbage quote bytes.
    let nonce = vault.challenge();
    assert!(matches!(
        vault
            .evaluate(&nonce, &blinded.0, &[0xAB; 120])
            .unwrap_err(),
        VaultError::QuoteInvalid(_)
    ));

    // Valid structure, but a measurement outside the appraisal policy
    // (unreviewed code must not reach k).
    let rogue = SimAttester {
        measurement: [0x66; MEASUREMENT_LEN],
    };
    let nonce = vault.challenge();
    let report_data = bind_report_data(&nonce, &blinded.0);
    let quote = rogue.quote(&report_data).unwrap();
    assert!(matches!(
        vault.evaluate(&nonce, &blinded.0, &quote).unwrap_err(),
        VaultError::QuoteInvalid(attestation::Error::MeasurementRejected)
    ));
}

#[test]
fn refuses_unbound_quote() {
    let vault = vault();
    let (_state, blinded) = voprf::blind(STABLE_ID).unwrap();
    let (_state2, other_blinded) = voprf::blind(b"someone-else-entirely").unwrap();

    // Quote bound to a DIFFERENT blinded input (the anti-grinding case:
    // one attested quote must not authorize evaluations on other inputs).
    let nonce = vault.challenge();
    let quote = SimAttester::default()
        .quote(&bind_report_data(&nonce, &other_blinded.0))
        .unwrap();
    assert_eq!(
        vault.evaluate(&nonce, &blinded.0, &quote).unwrap_err(),
        VaultError::NotBound
    );

    // Quote bound under a different (stale) nonce.
    let stale_nonce = vault.challenge();
    let fresh_nonce = vault.challenge();
    let quote = SimAttester::default()
        .quote(&bind_report_data(&stale_nonce, &blinded.0))
        .unwrap();
    assert_eq!(
        vault
            .evaluate(&fresh_nonce, &blinded.0, &quote)
            .unwrap_err(),
        VaultError::NotBound
    );
}

#[test]
fn nonce_lifecycle() {
    let vault = vault();
    let (_state, blinded) = voprf::blind(STABLE_ID).unwrap();

    // Never-issued nonce.
    let bogus = [0x42u8; 32];
    let quote = SimAttester::default()
        .quote(&bind_report_data(&bogus, &blinded.0))
        .unwrap();
    assert_eq!(
        vault.evaluate(&bogus, &blinded.0, &quote).unwrap_err(),
        VaultError::UnknownNonce
    );

    // A successful evaluation consumes the nonce: replaying the exact same
    // request afterwards fails.
    let nonce = vault.challenge();
    let quote = SimAttester::default()
        .quote(&bind_report_data(&nonce, &blinded.0))
        .unwrap();
    assert!(vault.evaluate(&nonce, &blinded.0, &quote).is_ok());
    assert_eq!(
        vault.evaluate(&nonce, &blinded.0, &quote).unwrap_err(),
        VaultError::UnknownNonce
    );
}

#[test]
fn debug_never_shows_key() {
    let vault = vault();
    let formatted = format!("{vault:?}");

    // Exactly the public key (which IS public), nothing else.
    let mut pk_hex = String::new();
    for b in vault.public_key() {
        pk_hex.push_str(&format!("{b:02x}"));
    }
    assert!(formatted.contains(&pk_hex));
    // The struct prints no other fields (k has no accessor at all; this
    // pins the redacted Debug shape against accidental derives later).
    assert!(formatted.starts_with("VoprfVault { public_key:"));
    assert!(formatted.ends_with(".. }"));
}
