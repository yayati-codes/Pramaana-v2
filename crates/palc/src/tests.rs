use crate::{
    derive, derive_inner, Error, C_COMMIT_LEN, DK_LEN, EK_LEN, MIN_OPRF_OUTPUT_LEN, PHI_LEN,
};

/// Fixed inputs for the golden vector and determinism runs.
const OPRF: [u8; 64] = [0x11; 64];
const SID: &[u8] = b"pramaana-golden-stable-id-v1";

/// Pinned Φ for (OPRF, SID). If this test fails after a dependency bump, the
/// derivation changed and EVERY enrolled identity would break — do not
/// "fix" the constant without understanding why it moved.
const GOLDEN_PHI_HEX: &str = "805903b68619495b0cae3e0d77aff316601b846faeae816d20fe96bf831ca729c1d0510450ec5d0fe20e8017159d92e641cad97873bc53be3db5fcb4cabd5808";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn golden_vector() {
    let palc = derive(&OPRF, SID).unwrap();
    assert_eq!(hex(&palc.phi), GOLDEN_PHI_HEX);
    assert_eq!(palc.phi.len(), PHI_LEN);
    assert_eq!(palc.c_commit.len(), C_COMMIT_LEN);
    assert_eq!(palc.sk_idr().len(), DK_LEN);
}

#[test]
fn determinism_1000_runs() {
    let reference = derive(&OPRF, SID).unwrap();
    for run in 1..1000 {
        let palc = derive(&OPRF, SID).unwrap();
        assert_eq!(palc.phi, reference.phi, "phi diverged at run {run}");
        assert_eq!(
            palc.c_commit, reference.c_commit,
            "c_commit diverged at run {run}"
        );
        assert_eq!(
            palc.sk_idr(),
            reference.sk_idr(),
            "sk_idr diverged at run {run}"
        );
    }
}

#[test]
fn distinct_inputs_distinct_phi() {
    let base = derive(&OPRF, SID).unwrap();

    // Hiding/binding sanity: any input change moves Φ ...
    let mut oprf_flipped = OPRF;
    oprf_flipped[0] ^= 0x01;
    let other_oprf = derive(&oprf_flipped, SID).unwrap();
    assert_ne!(base.phi, other_oprf.phi);

    let other_sid = derive(&OPRF, b"pramaana-golden-stable-id-v2").unwrap();
    assert_ne!(base.phi, other_sid.phi);
    assert_ne!(other_oprf.phi, other_sid.phi);

    // ... and no change keeps it fixed.
    let same = derive(&OPRF, SID).unwrap();
    assert_eq!(base.phi, same.phi);
    assert_eq!(base.c_commit[..EK_LEN], same.c_commit[..EK_LEN]);
}

#[test]
fn seed_zeroized_after_derive() {
    // DoD memory test, via the post-wipe observer seam: the closure runs on
    // the very buffers the derivation used, after wiping, before they are
    // freed (no use-after-free).
    let mut observed = false;
    let palc = derive_inner(&OPRF, SID, |im| {
        assert!(
            im.seed.iter().all(|&b| b == 0),
            "seed must be zeroized before derive returns"
        );
        assert!(im.is_wiped(), "all PII-derived intermediates must be wiped");
        observed = true;
    })
    .unwrap();
    assert!(observed, "post-wipe observer did not run");
    // The wipe must not have damaged the outputs.
    assert_eq!(palc.c_commit.len(), C_COMMIT_LEN);
    assert!(palc.phi.iter().any(|&b| b != 0));
}

#[test]
fn input_validation() {
    let short = [0u8; MIN_OPRF_OUTPUT_LEN - 1];
    assert_eq!(
        derive(&short, SID).unwrap_err(),
        Error::OprfOutputTooShort {
            got: MIN_OPRF_OUTPUT_LEN - 1
        }
    );
    assert_eq!(derive(&OPRF, b"").unwrap_err(), Error::StableIdEmpty);
}
