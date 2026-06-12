//! Registry R abstraction (§2 steps 11–12). `InMemoryRegistry` mirrors
//! contracts/src/Registry.sol semantics — verify Gate Z, enforce dedup
//! novelty, record Φ — so the orchestration logic is real and testable now;
//! the on-chain implementation arrives with the sdk/contracts wiring.

use std::collections::HashSet;
use std::sync::Mutex;

use attestation::sim::SimVerifier;
use attestation::{verify_report_data_binding, Verifier};

/// Domain value used as the "nonce" in the Gate Z report_data binding: the
/// sim proof binds the quote to Φ under this context label.
pub const GATE_Z_CONTEXT: &[u8] = b"pramaana-gate-z-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("gate Z proof rejected: {0}")]
    GateZRejected(String),
    #[error("dedup tag already registered (Sybil block)")]
    AlreadyRegistered,
    #[error("registry backend error: {0}")]
    Backend(String),
}

pub trait Registry {
    fn is_seen(&self, dedup_tag: &[u8; 32]) -> Result<bool, RegistryError>;
    /// §2 step 12: verify the Gate Z proof, and only then record Φ.
    fn register(
        &self,
        phi: &[u8; 64],
        dedup_tag: &[u8; 32],
        gatez_proof: &[u8],
    ) -> Result<(), RegistryError>;
}

/// Sim-mode registry: same rules as Registry.sol, in memory.
#[derive(Default)]
pub struct InMemoryRegistry {
    verifier: SimVerifier,
    dedup_seen: Mutex<HashSet<[u8; 32]>>,
    phis: Mutex<HashSet<[u8; 64]>>,
}

impl InMemoryRegistry {
    pub fn identity_count(&self) -> usize {
        self.phis.lock().expect("registry poisoned").len()
    }
}

impl Registry for InMemoryRegistry {
    fn is_seen(&self, dedup_tag: &[u8; 32]) -> Result<bool, RegistryError> {
        Ok(self
            .dedup_seen
            .lock()
            .expect("registry poisoned")
            .contains(dedup_tag))
    }

    fn register(
        &self,
        phi: &[u8; 64],
        dedup_tag: &[u8; 32],
        gatez_proof: &[u8],
    ) -> Result<(), RegistryError> {
        // R verifies, and only then records (§2 step 12).
        let verified = self
            .verifier
            .verify(gatez_proof)
            .map_err(|e| RegistryError::GateZRejected(e.to_string()))?;
        verify_report_data_binding(&verified, GATE_Z_CONTEXT, phi)
            .map_err(|e| RegistryError::GateZRejected(e.to_string()))?;

        let mut seen = self.dedup_seen.lock().expect("registry poisoned");
        if !seen.insert(*dedup_tag) {
            return Err(RegistryError::AlreadyRegistered);
        }
        self.phis.lock().expect("registry poisoned").insert(*phi);
        Ok(())
    }
}
