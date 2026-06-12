//! TDX attestation (ARCHITECTURE.md §2 steps 1/7/9/12, §5, §6): three
//! interchangeable backends so the SAME gate logic runs everywhere.
//!
//! - `sim` (default): deterministic mock quotes; any laptop.
//! - `tdx`: configfs-tsm quote gen + tdx-quote parse/QE-sig + dcap-rs
//!   collateral verification; bare TDX host.
//! - `dstack`: quotes + RA-TLS certs from the dstack guest agent
//!   (/var/run/dstack.sock); Phala Cloud.
//!
//! ## report_data convention (all backends)
//! `report_data = SHA-512(domain ‖ len(nonce) ‖ nonce ‖ value)` via
//! [`bind_report_data`] (Gate 0: value = ephemeral TLS pubkey; Gate b:
//! value = blinded input). The quote's report_data FIELD stores
//! `sha256(report_data) ‖ 0^32` ([`quoted_report_data`]) — attesters submit
//! the wrapped form, so verifiers always compare against the sha256
//! wrapping, never the raw 64 bytes. Attestation gates ACTIONS, not
//! computation on public data (THREAT_MODEL.md d).

#[cfg(feature = "dstack")]
pub mod dstack;
#[cfg(feature = "sim")]
pub mod sim;
#[cfg(feature = "tdx")]
pub mod tdx;

use sha2::{Digest, Sha256, Sha512};

/// Raw report_data length (TDX field size).
pub const REPORT_DATA_LEN: usize = 64;
/// MRTD / measurement length (SHA-384 size).
pub const MEASUREMENT_LEN: usize = 48;

const BIND_DOMAIN: &[u8] = b"pramaana-report-data-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("quote is malformed: {0}")]
    Malformed(&'static str),
    #[error("measurement is not in the verifier's allowlist")]
    MeasurementRejected,
    #[error("report_data does not bind the expected (nonce, value)")]
    BindingMismatch,
    #[error("backend error: {0}")]
    Backend(String),
}

/// The 64-byte report_data input: H(nonce ‖ value), length-framed and
/// domain-separated (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportData(pub [u8; REPORT_DATA_LEN]);

/// Gate 0: `bind_report_data(nonce, ephemeral_tls_pubkey)`.
/// Gate b: `bind_report_data(nonce, blinded_input)`.
///
/// The nonce length is framed so (nonce, value) boundaries are unambiguous:
/// ("ab", "c") and ("a", "bc") yield different report_data.
pub fn bind_report_data(nonce: &[u8], value: &[u8]) -> ReportData {
    let mut h = Sha512::new();
    h.update(BIND_DOMAIN);
    h.update((nonce.len() as u64).to_le_bytes());
    h.update(nonce);
    h.update(value);
    ReportData(h.finalize().into())
}

/// What the quote's report_data field actually stores: dstack/TDX flows put
/// `sha256(report_data)` (zero-padded to 64) in the quote, NOT the raw
/// bytes. Attesters submit this; verifiers compare against it.
pub fn quoted_report_data(report_data: &ReportData) -> [u8; REPORT_DATA_LEN] {
    let mut stored = [0u8; REPORT_DATA_LEN];
    stored[..32].copy_from_slice(&Sha256::digest(report_data.0));
    stored
}

/// Backend-independent result of verifying a quote's structure/signature.
/// Binding to a (nonce, value) is a SEPARATE step: [`verify_report_data_binding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    pub measurement: [u8; MEASUREMENT_LEN],
    /// The report_data field as stored in the quote (sha256-wrapped form).
    pub stored_report_data: [u8; REPORT_DATA_LEN],
    pub backend: &'static str,
}

/// Generates quotes over a report_data (submits the sha256-wrapped form).
pub trait Attester {
    fn quote(&self, report_data: &ReportData) -> Result<Vec<u8>, Error>;
}

/// Verifies quote structure + provenance and extracts measurement/report_data.
pub trait Verifier {
    fn verify(&self, quote: &[u8]) -> Result<VerifiedQuote, Error>;
}

/// The shared gate check (identical for every backend): does this verified
/// quote bind the expected (nonce, value)?
pub fn verify_report_data_binding(
    quote: &VerifiedQuote,
    nonce: &[u8],
    value: &[u8],
) -> Result<(), Error> {
    let expected = quoted_report_data(&bind_report_data(nonce, value));
    // Not secret material (the quote is public), so plain comparison is fine.
    if quote.stored_report_data == expected {
        Ok(())
    } else {
        Err(Error::BindingMismatch)
    }
}

#[cfg(test)]
mod tests;
