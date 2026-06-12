//! SIM backend (§6 default): deterministic mock quotes so the full
//! enrollment flow runs on any machine. Layout:
//! `b"PRAMSIM1" ‖ measurement (48) ‖ stored_report_data (64)` = 120 bytes.

use crate::{
    quoted_report_data, Attester, Error, ReportData, VerifiedQuote, Verifier, MEASUREMENT_LEN,
    REPORT_DATA_LEN,
};

const MAGIC: &[u8; 8] = b"PRAMSIM1";
const QUOTE_LEN: usize = 8 + MEASUREMENT_LEN + REPORT_DATA_LEN;

/// The measurement the sim "hardware" reports (stand-in for MRTD of the
/// reviewed enclave image). GateZVerifier's sim mode and the sim appraisal
/// policy both reference it.
pub const SIM_MEASUREMENT: [u8; MEASUREMENT_LEN] = [0x5A; MEASUREMENT_LEN];

pub struct SimAttester {
    pub measurement: [u8; MEASUREMENT_LEN],
}

impl Default for SimAttester {
    fn default() -> Self {
        Self {
            measurement: SIM_MEASUREMENT,
        }
    }
}

impl Attester for SimAttester {
    fn quote(&self, report_data: &ReportData) -> Result<Vec<u8>, Error> {
        let mut quote = Vec::with_capacity(QUOTE_LEN);
        quote.extend_from_slice(MAGIC);
        quote.extend_from_slice(&self.measurement);
        // Same convention as the real backends: the quote field stores the
        // sha256-wrapped report_data, not the raw bytes.
        quote.extend_from_slice(&quoted_report_data(report_data));
        Ok(quote)
    }
}

/// Sim appraisal policy: an allowlist of measurements ("reviewed code").
pub struct SimVerifier {
    pub allowed_measurements: Vec<[u8; MEASUREMENT_LEN]>,
}

impl Default for SimVerifier {
    fn default() -> Self {
        Self {
            allowed_measurements: vec![SIM_MEASUREMENT],
        }
    }
}

impl Verifier for SimVerifier {
    fn verify(&self, quote: &[u8]) -> Result<VerifiedQuote, Error> {
        if quote.len() != QUOTE_LEN {
            return Err(Error::Malformed("sim quote must be 120 bytes"));
        }
        if &quote[..8] != MAGIC {
            return Err(Error::Malformed("bad sim magic"));
        }
        let mut measurement = [0u8; MEASUREMENT_LEN];
        measurement.copy_from_slice(&quote[8..8 + MEASUREMENT_LEN]);
        if !self.allowed_measurements.contains(&measurement) {
            return Err(Error::MeasurementRejected);
        }
        let mut stored_report_data = [0u8; REPORT_DATA_LEN];
        stored_report_data.copy_from_slice(&quote[8 + MEASUREMENT_LEN..]);
        Ok(VerifiedQuote {
            measurement,
            stored_report_data,
            backend: "sim",
        })
    }
}
