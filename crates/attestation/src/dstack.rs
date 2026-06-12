//! dstack backend (feature `dstack`): quotes + RA-TLS certs from the dstack
//! guest agent over /var/run/dstack.sock (Phala Cloud deployment target).
//!
//! Wraps `dstack_sdk::DstackClient` (verified against SDK 0.1.3 source):
//! `new(None)` probes the standard socket paths and honors
//! `DSTACK_SIMULATOR_ENDPOINT`; `get_quote` takes ≤ 64 raw bytes — we submit
//! the sha256-wrapped report_data per the crate-wide convention.
//!
//! Quotes produced here are ordinary TDX quotes: verify them with
//! `tdx::TdxVerifier` (feature `tdx`) on the relying side. The SDK is async;
//! the sync [`Attester`] impl runs a private current-thread tokio runtime.

use dstack_sdk::dstack_client::{DstackClient, GetTlsKeyResponse, TlsKeyConfig};
use tokio::runtime::{Builder, Runtime};

use crate::{quoted_report_data, Attester, Error, ReportData};

pub struct DstackAttester {
    client: DstackClient,
    runtime: Runtime,
}

impl DstackAttester {
    /// `endpoint`: None = auto-discover the guest-agent socket (or
    /// `DSTACK_SIMULATOR_ENDPOINT`); Some(path-or-http-url) to override.
    pub fn new(endpoint: Option<&str>) -> Result<Self, Error> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Backend(format!("tokio runtime: {e}")))?;
        Ok(Self {
            client: DstackClient::new(endpoint),
            runtime,
        })
    }

    /// Async quote generation (hex quote decoded to raw bytes).
    pub async fn quote_async(&self, report_data: &ReportData) -> Result<Vec<u8>, Error> {
        let stored = quoted_report_data(report_data);
        let response = self
            .client
            .get_quote(stored.to_vec())
            .await
            .map_err(|e| Error::Backend(format!("dstack get_quote: {e}")))?;
        decode_hex(&response.quote)
    }

    /// RA-TLS key + certificate chain from the guest agent (Gate 0 channel).
    pub async fn tls_key_async(&self, config: TlsKeyConfig) -> Result<GetTlsKeyResponse, Error> {
        self.client
            .get_tls_key(config)
            .await
            .map_err(|e| Error::Backend(format!("dstack get_tls_key: {e}")))
    }
}

impl Attester for DstackAttester {
    fn quote(&self, report_data: &ReportData) -> Result<Vec<u8>, Error> {
        self.runtime.block_on(self.quote_async(report_data))
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim().trim_start_matches("0x");
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Malformed("quote is not valid hex"));
    }
    Ok(s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("checked hex") as u8;
            let lo = (pair[1] as char).to_digit(16).expect("checked hex") as u8;
            (hi << 4) | lo
        })
        .collect())
}
