//! VOPRF Vault O (ARCHITECTURE.md §2 steps 7–9, §5): holds the OPRF key k
//! and serves attested evaluations — the Gate b server side.
//!
//! Key handling: k is derived from a seed via RFC 9497 DeriveKeyPair inside
//! `voprf::server::Vault` and has NO accessor; the upstream type zeroizes on
//! drop. In SIM mode the caller supplies the seed directly; the real path
//! obtains it from TDX sealed storage / the dstack KMS (`get_key`) so it
//! only ever exists inside the CVM. Nothing in this crate logs or formats k
//! — `Debug` prints the public key only.
//!
//! Gate b protocol:
//! 1. T asks for a [`VoprfVault::challenge`] nonce (single use).
//! 2. T quotes with `report_data = bind_report_data(nonce, blinded_input)`.
//! 3. [`VoprfVault::evaluate`] burns the nonce, verifies the quote, checks
//!    the binding, and only then evaluates under k, returning the
//!    evaluation + DLEQ proof for client-side Gate k verification.

#[cfg(feature = "http-server")]
pub mod http;

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

use attestation::{verify_report_data_binding, Verifier};
use rand_core::{OsRng, RngCore};
use voprf::server::Vault;
use voprf::{ELEMENT_LEN, PROOF_LEN};

pub const NONCE_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("challenge nonce is unknown, expired, or already used")]
    UnknownNonce,
    #[error("requester quote rejected: {0}")]
    QuoteInvalid(attestation::Error),
    #[error("quote report_data is not bound to this nonce + blinded input")]
    NotBound,
    #[error("voprf evaluation failed: {0}")]
    Voprf(voprf::Error),
}

/// Successful Gate b evaluation: feed both to `voprf::unblind` (Gate k).
/// Both fields are public wire values (safe to Debug).
#[derive(Debug)]
pub struct EvaluateOk {
    pub evaluation: [u8; ELEMENT_LEN],
    pub proof: [u8; PROOF_LEN],
}

/// The service O. Generic over the quote verifier so the same gate logic
/// runs with `attestation::sim::SimVerifier` locally and the tdx/dstack
/// verifiers in deployment.
pub struct VoprfVault<V: Verifier> {
    vault: Vault,
    verifier: V,
    outstanding_nonces: Mutex<HashSet<[u8; NONCE_LEN]>>,
}

impl<V: Verifier> VoprfVault<V> {
    /// `seed` is the sealed key material (SIM: caller-provided; real path:
    /// TDX sealed storage / dstack KMS). `info` domain-separates key
    /// derivation per RFC 9497 DeriveKeyPair.
    pub fn from_seed(seed: &[u8], info: &[u8], verifier: V) -> Result<Self, VaultError> {
        let vault = Vault::from_seed(seed, info).map_err(VaultError::Voprf)?;
        Ok(Self {
            vault,
            verifier,
            outstanding_nonces: Mutex::new(HashSet::new()),
        })
    }

    /// The committed public key PK = k·G that clients verify the DLEQ
    /// proof against.
    pub fn public_key(&self) -> [u8; ELEMENT_LEN] {
        self.vault.public_key()
    }

    /// Issue a fresh single-use challenge nonce for Gate b.
    pub fn challenge(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        self.outstanding_nonces
            .lock()
            .expect("nonce set poisoned")
            .insert(nonce);
        nonce
    }

    /// Gate b: attested evaluation.
    ///
    /// The nonce is burned FIRST — even when the quote or binding check
    /// fails — so a rejected request cannot be retried under the same
    /// challenge: every grinding attempt costs a fresh challenge and a
    /// fresh quote bound to it.
    pub fn evaluate(
        &self,
        nonce: &[u8; NONCE_LEN],
        blinded_input: &[u8],
        requester_quote: &[u8],
    ) -> Result<EvaluateOk, VaultError> {
        if !self
            .outstanding_nonces
            .lock()
            .expect("nonce set poisoned")
            .remove(nonce)
        {
            return Err(VaultError::UnknownNonce);
        }

        let verified = self
            .verifier
            .verify(requester_quote)
            .map_err(VaultError::QuoteInvalid)?;
        verify_report_data_binding(&verified, nonce, blinded_input)
            .map_err(|_| VaultError::NotBound)?;

        let (evaluation, proof) = self
            .vault
            .blind_evaluate(&mut OsRng, blinded_input)
            .map_err(VaultError::Voprf)?;
        Ok(EvaluateOk { evaluation, proof })
    }
}

impl<V: Verifier> fmt::Debug for VoprfVault<V> {
    /// Shows the committed public key ONLY — k must never reach any log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut pk_hex = String::with_capacity(ELEMENT_LEN * 2);
        for b in self.public_key() {
            pk_hex.push_str(&format!("{b:02x}"));
        }
        f.debug_struct("VoprfVault")
            .field("public_key", &pk_hex)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
