//! PALC — Post-quantum Anonymous Lattice Commitment (ARCHITECTURE.md §2 step 10, §5).
//!
//! ```text
//! h_stable = SHA3-512(stable_id)
//! seed     = HKDF-SHA3-512(salt = 64 zero bytes, IKM = oprf_output ‖ h_stable,
//!                          info = "pramaana-v1", L = 64)
//! (ek, dk) = ML-KEM-1024.KeyGen_internal(seed[0..32], seed[32..64])   [FIPS 203]
//! m        = SHA3-512(seed)[0..32]
//! (ct, K)  = ML-KEM-1024.Encaps_internal(ek, m)                       [FIPS 203]
//! C_commit = ek ‖ ct
//! Φ        = SHA3-512(C_commit);   sk_IdR = dk
//! ```
//!
//! Both `*_internal` functions are fully specified by FIPS 203, so identical
//! inputs give byte-identical outputs in any compliant implementation: Φ and
//! sk_IdR are exactly recomputable forever (recovery-by-rescan, §4) and
//! survive future KEM-crate swaps. The golden test in `tests.rs` pins this.
//!
//! Every PII-derived intermediate this crate allocates is zeroized before
//! [`derive`] returns (§4). Out of scope, by API limitation: hash states
//! inside sha3/hkdf and libcrux's internal copies (it takes the seed by
//! value); per THREAT_MODEL.md the enclave boundary is the backstop for those.

use core::fmt;

use hkdf::Hkdf;
use libcrux_ml_kem::mlkem1024;
use sha3::{Digest, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF output length: 64 bytes = ML-KEM-1024 KeyGen_internal's (d ‖ z).
pub const SEED_LEN: usize = 64;
/// Φ is a SHA3-512 digest.
pub const PHI_LEN: usize = 64;
/// ML-KEM-1024 encapsulation (public) key.
pub const EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext.
pub const CT_LEN: usize = 1568;
/// C_commit = ek ‖ ct.
pub const C_COMMIT_LEN: usize = EK_LEN + CT_LEN;
/// ML-KEM-1024 decapsulation (private) key.
pub const DK_LEN: usize = 3168;
/// A VOPRF output is a group element ≥ 32 bytes; anything shorter is a bug.
pub const MIN_OPRF_OUTPUT_LEN: usize = 32;

const ZERO_SALT: [u8; 64] = [0u8; 64];
const HKDF_INFO: &[u8] = b"pramaana-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("oprf_output must be at least {MIN_OPRF_OUTPUT_LEN} bytes, got {got}")]
    OprfOutputTooShort { got: usize },
    #[error("stable_id must not be empty")]
    StableIdEmpty,
}

/// Result of the PALC derivation. Holds sk_IdR: zeroized on drop, no Clone,
/// redacted Debug (same hygiene as `AadhaarRecord`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Palc {
    /// Φ = SHA3-512(C_commit) — the master identity. Public.
    pub phi: [u8; PHI_LEN],
    /// C_commit = ek ‖ ct (always `C_COMMIT_LEN` bytes). Public.
    pub c_commit: Vec<u8>,
    /// sk_IdR = the ML-KEM-1024 decapsulation key (always `DK_LEN` bytes).
    /// Secret; recomputable by re-scan + re-derive, NEVER stored (§2 step 13).
    sk_idr: Vec<u8>,
}

impl Palc {
    pub fn sk_idr(&self) -> &[u8] {
        &self.sk_idr
    }
}

impl fmt::Debug for Palc {
    /// Redacted: never prints sk_IdR.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut phi_hex = String::with_capacity(PHI_LEN * 2);
        for b in self.phi {
            phi_hex.push_str(&format!("{b:02x}"));
        }
        f.debug_struct("Palc")
            .field("phi", &phi_hex)
            .field("c_commit_len", &self.c_commit.len())
            .finish_non_exhaustive()
    }
}

/// Every PII-derived buffer the derivation allocates, gathered so they can be
/// wiped together and inspected (post-wipe) by the memory test.
pub(crate) struct Intermediates {
    pub(crate) h_stable: [u8; 64],
    pub(crate) ikm: Vec<u8>,
    pub(crate) seed: [u8; SEED_LEN],
    pub(crate) h_seed: [u8; 64],
    pub(crate) m: [u8; 32],
    pub(crate) shared_secret: [u8; 32],
}

impl Default for Intermediates {
    fn default() -> Self {
        Self {
            h_stable: [0u8; 64],
            ikm: Vec::new(),
            seed: [0u8; SEED_LEN],
            h_seed: [0u8; 64],
            m: [0u8; 32],
            shared_secret: [0u8; 32],
        }
    }
}

impl Intermediates {
    fn wipe(&mut self) {
        self.h_stable.zeroize();
        self.ikm.zeroize();
        self.seed.zeroize();
        self.h_seed.zeroize();
        self.m.zeroize();
        self.shared_secret.zeroize();
    }

    /// True iff every buffer is all-zero (`Vec::zeroize` wipes the full
    /// capacity and clears, so emptiness is the observable for `ikm`).
    #[cfg(test)]
    pub(crate) fn is_wiped(&self) -> bool {
        self.h_stable.iter().all(|&b| b == 0)
            && self.ikm.is_empty()
            && self.seed.iter().all(|&b| b == 0)
            && self.h_seed.iter().all(|&b| b == 0)
            && self.m.iter().all(|&b| b == 0)
            && self.shared_secret.iter().all(|&b| b == 0)
    }
}

/// Derive (Φ, sk_IdR, C_commit) from the unblinded VOPRF output and the
/// stable timestamp-stripped identifier (§2 step 10).
pub fn derive(oprf_output: &[u8], stable_id: &[u8]) -> Result<Palc, Error> {
    derive_inner(oprf_output, stable_id, |_| {})
}

/// Implementation seam: `post_wipe` runs after the intermediates are wiped
/// but before their allocations are freed, letting the memory test assert
/// zeroization on the actual buffers without use-after-free.
pub(crate) fn derive_inner(
    oprf_output: &[u8],
    stable_id: &[u8],
    post_wipe: impl FnOnce(&Intermediates),
) -> Result<Palc, Error> {
    if oprf_output.len() < MIN_OPRF_OUTPUT_LEN {
        return Err(Error::OprfOutputTooShort {
            got: oprf_output.len(),
        });
    }
    if stable_id.is_empty() {
        return Err(Error::StableIdEmpty);
    }

    let mut im = Intermediates::default();

    im.h_stable = Sha3_512::digest(stable_id).into();
    im.ikm = Vec::with_capacity(oprf_output.len() + im.h_stable.len());
    im.ikm.extend_from_slice(oprf_output);
    im.ikm.extend_from_slice(&im.h_stable);

    Hkdf::<Sha3_512>::new(Some(&ZERO_SALT), &im.ikm)
        .expand(HKDF_INFO, &mut im.seed)
        .expect("SEED_LEN is far below HKDF's 255 * hash_len limit");
    debug_assert!(
        im.seed.iter().any(|&b| b != 0),
        "HKDF output cannot plausibly be all-zero"
    );

    // FIPS 203 KeyGen_internal(d = seed[0..32], z = seed[32..64]).
    // (libcrux takes the seed by value; that copy is outside our wipe scope.)
    let key_pair = mlkem1024::generate_key_pair(im.seed);

    // m = SHA3-512(seed) truncated to ML-KEM's 32-byte message space.
    im.h_seed = Sha3_512::digest(im.seed).into();
    im.m.copy_from_slice(&im.h_seed[..32]);

    // FIPS 203 Encaps_internal(ek, m). The shared secret K is an unused
    // byproduct here — the ciphertext is what commits to the seed.
    let (ct, mut shared_secret) = mlkem1024::encapsulate(key_pair.public_key(), im.m);
    im.shared_secret.copy_from_slice(&shared_secret);
    shared_secret.zeroize();

    let mut c_commit = Vec::with_capacity(C_COMMIT_LEN);
    c_commit.extend_from_slice(key_pair.public_key().as_slice());
    c_commit.extend_from_slice(ct.as_slice());
    let phi: [u8; PHI_LEN] = Sha3_512::digest(&c_commit).into();

    let palc = Palc {
        phi,
        c_commit,
        sk_idr: key_pair.private_key().as_slice().to_vec(),
    };

    im.wipe();
    post_wipe(&im);
    Ok(palc)
}

#[cfg(test)]
mod tests;
