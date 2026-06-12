use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::server::Vault;
use crate::{blind, blind_with_rng, unblind, Error, ELEMENT_LEN, OUTPUT_LEN, PROOF_LEN};

const INPUT: &[u8] = b"4242|Asha Example|01-01-1990|F|141002"; // stable-id-shaped
const VAULT_KEY: &[u8] = b"pramaana-test-vault-key-seed-0001";

fn vault() -> Vault {
    Vault::from_seed(VAULT_KEY, b"pramaana-vault-v1").unwrap()
}

#[test]
fn correctness_matches_direct_prf() {
    let vault = vault();
    let mut rng = StdRng::seed_from_u64(7);

    // Protocol run 1.
    let (state, blinded) = blind_with_rng(INPUT, &mut rng).unwrap();
    let (evaluation, proof) = vault.blind_evaluate(&mut rng, &blinded.0).unwrap();
    let out1 = unblind(state, INPUT, &evaluation, &proof, &vault.public_key()).unwrap();

    // DoD: Unblind(Eval(Blind(x))) == PRF(k, x).
    assert_eq!(out1.as_bytes(), &vault.evaluate(INPUT).unwrap());

    // Run 2 with a fresh blinding factor (and the OsRng path): same output —
    // the blind cancels exactly.
    let (state2, blinded2) = blind(INPUT).unwrap();
    assert_ne!(blinded.0, blinded2.0, "fresh r must give a fresh blinding");
    let (eval2, proof2) = vault.blind_evaluate(&mut rng, &blinded2.0).unwrap();
    let out2 = unblind(state2, INPUT, &eval2, &proof2, &vault.public_key()).unwrap();
    assert_eq!(out1.as_bytes(), out2.as_bytes());

    // Different input → different PRF output.
    let (state3, blinded3) = blind(b"other-stable-id").unwrap();
    let (eval3, proof3) = vault.blind_evaluate(&mut rng, &blinded3.0).unwrap();
    let out3 = unblind(
        state3,
        b"other-stable-id",
        &eval3,
        &proof3,
        &vault.public_key(),
    )
    .unwrap();
    assert_ne!(out1.as_bytes(), out3.as_bytes());
}

#[test]
fn verifiability_rejects_bad_proofs() {
    let vault = vault();
    let mut rng = StdRng::seed_from_u64(8);

    // (a) Bit-flipped proof.
    let (state, blinded) = blind_with_rng(INPUT, &mut rng).unwrap();
    let (evaluation, mut proof) = vault.blind_evaluate(&mut rng, &blinded.0).unwrap();
    proof[10] ^= 0x01;
    assert_eq!(
        unblind(state, INPUT, &evaluation, &proof, &vault.public_key()).unwrap_err(),
        Error::ProofRejected
    );

    // (b) Bit-flipped evaluation (proof no longer matches it). Flipping a
    // byte of a compressed ristretto encoding may also make it non-canonical,
    // so either rejection path is a pass — but never Ok.
    let (state, blinded) = blind_with_rng(INPUT, &mut rng).unwrap();
    let (mut evaluation, proof) = vault.blind_evaluate(&mut rng, &blinded.0).unwrap();
    evaluation[5] ^= 0x01;
    let err = unblind(state, INPUT, &evaluation, &proof, &vault.public_key()).unwrap_err();
    assert!(
        matches!(err, Error::ProofRejected | Error::MalformedWire(_)),
        "got {err:?}"
    );

    // (c) The de-anonymization vector (THREAT_MODEL b): a SECOND vault with
    // its own key answers honestly — its own proof verifies against ITS key —
    // but the client checks against the COMMITTED key of vault 1 and must
    // reject. This is what stops per-user-key linking attacks.
    let rogue =
        Vault::from_seed(b"rogue-vault-with-per-user-key-000", b"pramaana-vault-v1").unwrap();
    let (state, blinded) = blind_with_rng(INPUT, &mut rng).unwrap();
    let (evaluation, proof) = rogue.blind_evaluate(&mut rng, &blinded.0).unwrap();
    assert_eq!(
        unblind(state, INPUT, &evaluation, &proof, &vault.public_key()).unwrap_err(),
        Error::ProofRejected
    );

    // Garbage wire bytes.
    let (state, _) = blind_with_rng(INPUT, &mut rng).unwrap();
    assert!(matches!(
        unblind(
            state,
            INPUT,
            &[0xAB; 7],
            &[0u8; PROOF_LEN],
            &vault.public_key()
        )
        .unwrap_err(),
        Error::MalformedWire(_)
    ));
}

#[test]
fn blindness_statistical() {
    // Blindness itself is information-theoretic: blinded = r·H(x) with r
    // uniform is uniform on the group for ANY x. This test is a smoke test
    // of the blinding wiring (it would catch a constant/reused r or a
    // skipped multiplication), not a proof of the property.
    const SAMPLES: usize = 2000;
    // Structural bits of a compressed ristretto encoding (canonical field
    // element s < 2^255 - 19 with the "non-negative" = EVEN representative):
    // bit 0 (parity) and bit 255 are always 0; bits 1..=254 are statistically
    // uniform for a uniform group element.
    // 5σ bounds at n = 2000: 0.5 ± 5·√(0.25/2000) ≈ 0.5 ± 0.056.
    const LO: f64 = 0.42;
    const HI: f64 = 0.58;

    let mut rng = StdRng::seed_from_u64(9);
    for input in [INPUT, b"a completely different identity".as_slice()] {
        let mut seen = std::collections::HashSet::with_capacity(SAMPLES);
        let mut bit_counts = [0u32; 256];
        for _ in 0..SAMPLES {
            let (_state, blinded) = blind_with_rng(input, &mut rng).unwrap();
            assert!(
                seen.insert(blinded.0),
                "two blindings of the same input must never collide"
            );
            for (bit, count) in bit_counts.iter_mut().enumerate() {
                if blinded.0[bit / 8] >> (bit % 8) & 1 == 1 {
                    *count += 1;
                }
            }
        }
        assert_eq!(bit_counts[0], 0, "ristretto parity bit must be 0");
        assert_eq!(bit_counts[255], 0, "field elements are < 2^255");
        for (bit, &count) in bit_counts.iter().enumerate().take(255).skip(1) {
            let freq = f64::from(count) / SAMPLES as f64;
            assert!(
                (LO..=HI).contains(&freq),
                "bit {bit} frequency {freq} outside [{LO}, {HI}] for input {input:?}"
            );
        }
    }
}

#[test]
fn wire_lengths_and_input_validation() {
    let vault = vault();
    let mut rng = StdRng::seed_from_u64(10);

    let (_state, blinded) = blind_with_rng(INPUT, &mut rng).unwrap();
    let (evaluation, proof) = vault.blind_evaluate(&mut rng, &blinded.0).unwrap();
    assert_eq!(blinded.0.len(), ELEMENT_LEN);
    assert_eq!(evaluation.len(), ELEMENT_LEN);
    assert_eq!(proof.len(), PROOF_LEN);
    assert_eq!(vault.public_key().len(), ELEMENT_LEN);
    assert_eq!(vault.evaluate(INPUT).unwrap().len(), OUTPUT_LEN);

    assert_eq!(blind(b"").unwrap_err(), Error::EmptyInput);
    // (BlindingState is consumed by unblind — single-use is enforced at
    // compile time by move semantics.)
}
