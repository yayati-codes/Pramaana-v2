//! Bare-TDX backend (feature `tdx`): quote generation via configfs-tsm,
//! parsing/QE-signature via `tdx-quote`, full DCAP collateral verification
//! via Automata's `dcap-rs`. Compiles without hardware; needs a TDX host
//! (configfs at /sys/kernel/config) at runtime.
//!
//! Verification levels:
//! 1. [`TdxVerifier::verify`] (no collateral): parse + QE signature check —
//!    structural integrity, NOT chain-of-trust to Intel.
//! 2. [`TdxVerifier::verify_with_collateral`]: full DCAP v4 verification
//!    against Intel collateral (TCB info, QE identity, root CA).

use dcap_rs::types::collaterals::IntelCollateral;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::quotes::version_4::verify_quote_dcapv4;

use crate::{
    quoted_report_data, Attester, Error, ReportData, VerifiedQuote, Verifier, MEASUREMENT_LEN,
};

pub struct TdxAttester;

impl Attester for TdxAttester {
    fn quote(&self, report_data: &ReportData) -> Result<Vec<u8>, Error> {
        // Same convention as all backends: submit the sha256-wrapped form.
        configfs_tsm::create_tdx_quote(quoted_report_data(report_data))
            .map_err(|e| Error::Backend(format!("configfs-tsm: {e:?}")))
    }
}

/// Intel collateral for full DCAP verification (fetched out-of-band from
/// Intel PCS / PCCS; not bundled).
pub struct TdxCollateral {
    pub tcbinfo: Vec<u8>,
    pub qeidentity: Vec<u8>,
    pub intel_root_ca_der: Vec<u8>,
    pub sgx_tcb_signing_der: Vec<u8>,
}

#[derive(Default)]
pub struct TdxVerifier {
    collateral: Option<TdxCollateral>,
}

impl TdxVerifier {
    pub fn with_collateral(collateral: TdxCollateral) -> Self {
        Self {
            collateral: Some(collateral),
        }
    }

    fn extract(quote_bytes: &[u8]) -> Result<VerifiedQuote, Error> {
        let parsed = tdx_quote::Quote::from_bytes(quote_bytes)
            .map_err(|e| Error::Backend(format!("tdx-quote parse: {e:?}")))?;
        // QE signature check (structural provenance).
        parsed
            .verify()
            .map_err(|e| Error::Backend(format!("QE signature: {e:?}")))?;
        let measurement: [u8; MEASUREMENT_LEN] = parsed.mrtd();
        Ok(VerifiedQuote {
            measurement,
            stored_report_data: parsed.report_input_data(),
            backend: "tdx",
        })
    }

    /// Full DCAP v4 verification; requires collateral.
    pub fn verify_with_collateral(
        &self,
        quote_bytes: &[u8],
        current_time_secs: u64,
    ) -> Result<VerifiedQuote, Error> {
        let collateral = self
            .collateral
            .as_ref()
            .ok_or(Error::Malformed("no collateral configured"))?;

        let mut intel = IntelCollateral::new();
        intel.set_tcbinfo_bytes(&collateral.tcbinfo);
        intel.set_qeidentity_bytes(&collateral.qeidentity);
        intel.set_intel_root_ca_der(&collateral.intel_root_ca_der);
        intel.set_sgx_tcb_signing_der(&collateral.sgx_tcb_signing_der);

        let quote = QuoteV4::from_bytes(quote_bytes);
        // Panics inside dcap-rs on malformed input are a known sharp edge of
        // 0.1.0; callers should pre-validate with `verify` (tdx-quote parse).
        let _output = verify_quote_dcapv4(&quote, &intel, current_time_secs);
        Self::extract(quote_bytes)
    }
}

impl Verifier for TdxVerifier {
    /// Parse + QE-signature level (see module docs for the full-chain path).
    fn verify(&self, quote: &[u8]) -> Result<VerifiedQuote, Error> {
        Self::extract(quote)
    }
}
