//! Server-side evaluation (the vault O's core primitive; Gate b/k transport
//! and attestation live in voprf-vault, not here). Feature `server`.

use rand_core::{CryptoRng, RngCore};
use voprf_rfc9497::{BlindedElement, Group, Ristretto255, VoprfServer};

use crate::{Error, ELEMENT_LEN, OUTPUT_LEN, PROOF_LEN};

/// Holds the OPRF key k. Upstream type is ZeroizeOnDrop.
pub struct Vault {
    inner: VoprfServer<Ristretto255>,
}

impl Vault {
    /// Fresh random key.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, Error> {
        VoprfServer::new(rng)
            .map(|inner| Self { inner })
            .map_err(|_| Error::Internal)
    }

    /// Deterministic key from arbitrary seed bytes via RFC 9497
    /// DeriveKeyPair (the vault's sealed key material).
    pub fn from_seed(seed: &[u8], info: &[u8]) -> Result<Self, Error> {
        VoprfServer::new_from_seed(seed, info)
            .map(|inner| Self { inner })
            .map_err(|_| Error::MalformedWire("vault key seed"))
    }

    /// The committed public key PK = k·G that clients verify DLEQ against.
    pub fn public_key(&self) -> [u8; ELEMENT_LEN] {
        let mut pk = [0u8; ELEMENT_LEN];
        pk.copy_from_slice(&Ristretto255::serialize_elem(self.inner.get_public_key()));
        pk
    }

    /// Evaluate a blinded element and emit the DLEQ proof (RNG is for the
    /// proof nonce only; the evaluation itself is deterministic in k).
    pub fn blind_evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded: &[u8],
    ) -> Result<([u8; ELEMENT_LEN], [u8; PROOF_LEN]), Error> {
        let blinded = BlindedElement::<Ristretto255>::deserialize(blinded)
            .map_err(|_| Error::MalformedWire("blinded message"))?;
        let result = self.inner.blind_evaluate(rng, &blinded);

        let mut evaluation = [0u8; ELEMENT_LEN];
        evaluation.copy_from_slice(&result.message.serialize());
        let mut proof = [0u8; PROOF_LEN];
        proof.copy_from_slice(&result.proof.serialize());
        Ok((evaluation, proof))
    }

    /// Direct PRF(k, x) — what an honest protocol run must reproduce.
    pub fn evaluate(&self, input: &[u8]) -> Result<[u8; OUTPUT_LEN], Error> {
        let output = self.inner.evaluate(input).map_err(|_| Error::Internal)?;
        let mut bytes = [0u8; OUTPUT_LEN];
        bytes.copy_from_slice(&output);
        Ok(bytes)
    }
}
