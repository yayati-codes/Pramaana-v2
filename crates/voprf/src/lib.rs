//! VOPRF client side (ARCHITECTURE.md §2 steps 6–9, §5): blind/unblind +
//! DLEQ verification over ristretto255 (RFC 9497, ciphersuite
//! ristretto255-SHA512, via the maintained facebook/voprf crate).
//!
//! Load-bearing for privacy (THREAT_MODEL.md b): the issuer knows the full QR
//! contents, so the issuer-unknown vault key k is the ONLY thing preventing
//! issuer de-anonymization.
//!
//! Property notes:
//! - **Blindness is information-theoretic**: blinded = r·H(x) with r uniform;
//!   scalar multiplication by uniform r is a bijection on the prime-order
//!   group, so the blinded element is uniform regardless of x.
//! - **DLEQ verification binds to the COMMITTED key**: without it, a
//!   malicious vault could evaluate each user under a distinct key and
//!   partition/link users while outputs still look random. Never skip
//!   verification, never accept an unproven evaluation.

#[cfg(any(test, feature = "server"))]
pub mod server;

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use voprf_rfc9497::{EvaluationElement, Group, Proof, Ristretto255, VoprfClient};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compressed ristretto255 element (blinded message, evaluation, public key).
pub const ELEMENT_LEN: usize = 32;
/// DLEQ proof: two scalars (c, s).
pub const PROOF_LEN: usize = 64;
/// Finalize output: SHA-512.
pub const OUTPUT_LEN: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("input must not be empty")]
    EmptyInput,
    #[error("DLEQ proof rejected: evaluation is not under the committed vault key")]
    ProofRejected,
    #[error("malformed wire bytes: {0}")]
    MalformedWire(&'static str),
    #[error("voprf library error")]
    Internal,
}

fn map_voprf_error(e: voprf_rfc9497::Error) -> Error {
    match e {
        voprf_rfc9497::Error::ProofVerification => Error::ProofRejected,
        voprf_rfc9497::Error::Deserialization => Error::MalformedWire("element or proof"),
        _ => Error::Internal,
    }
}

/// Single-use client state: holds the blinding factor r (and the upstream
/// copy of the input). Upstream type is ZeroizeOnDrop; consumed by
/// [`unblind`] so it cannot be reused across evaluations.
pub struct BlindingState {
    inner: VoprfClient<Ristretto255>,
}

impl fmt::Debug for BlindingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlindingState(..)")
    }
}

/// The wire message sent to the vault. Reveals nothing about the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedMessage(pub [u8; ELEMENT_LEN]);

/// PRF(k, x): secret-derived (feeds the PALC seed). Zeroized on drop, no
/// Clone, redacted Debug.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OprfOutput([u8; OUTPUT_LEN]);

impl OprfOutput {
    pub fn as_bytes(&self) -> &[u8; OUTPUT_LEN] {
        &self.0
    }
}

impl fmt::Debug for OprfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OprfOutput([redacted; 64])")
    }
}

/// Blind `input` (the stable identifier) for evaluation by the vault.
/// Uses the OS RNG for the blinding factor.
pub fn blind(input: &[u8]) -> Result<(BlindingState, BlindedMessage), Error> {
    blind_with_rng(input, &mut rand_core::OsRng)
}

/// [`blind`] with a caller-supplied RNG (deterministic tests).
pub fn blind_with_rng<R: RngCore + CryptoRng>(
    input: &[u8],
    rng: &mut R,
) -> Result<(BlindingState, BlindedMessage), Error> {
    if input.is_empty() {
        return Err(Error::EmptyInput);
    }
    let result = VoprfClient::<Ristretto255>::blind(input, rng).map_err(map_voprf_error)?;
    let mut message = [0u8; ELEMENT_LEN];
    message.copy_from_slice(&result.message.serialize());
    Ok((
        BlindingState {
            inner: result.state,
        },
        BlindedMessage(message),
    ))
}

/// Verify the vault's DLEQ proof against its committed public key and
/// unblind. Consumes the single-use state. `input` must be the same bytes
/// passed to [`blind`] (Finalize binds the output to it).
pub fn unblind(
    state: BlindingState,
    input: &[u8],
    evaluation: &[u8],
    proof: &[u8],
    vault_pubkey: &[u8],
) -> Result<OprfOutput, Error> {
    let evaluation = EvaluationElement::<Ristretto255>::deserialize(evaluation)
        .map_err(|_| Error::MalformedWire("evaluation"))?;
    let proof =
        Proof::<Ristretto255>::deserialize(proof).map_err(|_| Error::MalformedWire("proof"))?;
    let pk = Ristretto255::deserialize_elem(vault_pubkey)
        .map_err(|_| Error::MalformedWire("vault_pubkey"))?;

    let output = state
        .inner
        .finalize(input, &evaluation, &proof, pk)
        .map_err(map_voprf_error)?;
    let mut bytes = [0u8; OUTPUT_LEN];
    bytes.copy_from_slice(&output);
    Ok(OprfOutput(bytes))
}

#[cfg(test)]
mod tests;
