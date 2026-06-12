//! HTTP client for the VOPRF vault O (Gate b transport).

use serde::{Deserialize, Serialize};

use crate::EnrollError;

#[derive(Deserialize)]
struct PubkeyResponse {
    public_key: String,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    nonce: String,
}

#[derive(Serialize)]
struct EvaluateRequest {
    nonce: String,
    blinded: String,
    quote: String,
}

#[derive(Deserialize)]
struct EvaluateResponse {
    evaluation: String,
    proof: String,
}

pub struct HttpVaultClient {
    base_url: String,
    agent: ureq::Agent,
    /// The vault's COMMITTED public key, fetched once and pinned at
    /// construction: every Gate k DLEQ verification runs against this, so a
    /// vault that later swaps keys (per-user-key attack) fails verification.
    public_key: [u8; 32],
}

impl HttpVaultClient {
    pub fn connect(base_url: &str) -> Result<Self, EnrollError> {
        let agent = ureq::Agent::new_with_defaults();
        let body: PubkeyResponse = agent
            .get(format!("{base_url}/pubkey"))
            .call()
            .map_err(vault_err)?
            .body_mut()
            .read_json()
            .map_err(vault_err)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            agent,
            public_key: decode_fixed::<32>(&body.public_key, "public_key")?,
        })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Gate b step 1: obtain a single-use challenge nonce from O.
    pub fn challenge(&self) -> Result<[u8; 32], EnrollError> {
        let body: ChallengeResponse = self
            .agent
            .post(format!("{}/challenge", self.base_url))
            .send_empty()
            .map_err(vault_err)?
            .body_mut()
            .read_json()
            .map_err(vault_err)?;
        decode_fixed::<32>(&body.nonce, "nonce")
    }

    /// Gate b step 3: attested evaluation request.
    pub fn evaluate(
        &self,
        nonce: &[u8; 32],
        blinded: &[u8; 32],
        quote: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), EnrollError> {
        let body: EvaluateResponse = self
            .agent
            .post(format!("{}/evaluate", self.base_url))
            .send_json(EvaluateRequest {
                nonce: hex::encode(nonce),
                blinded: hex::encode(blinded),
                quote: hex::encode(quote),
            })
            .map_err(vault_err)?
            .body_mut()
            .read_json()
            .map_err(vault_err)?;
        let evaluation = hex::decode(&body.evaluation)
            .map_err(|_| EnrollError::Vault("evaluation is not hex".into()))?;
        let proof =
            hex::decode(&body.proof).map_err(|_| EnrollError::Vault("proof is not hex".into()))?;
        Ok((evaluation, proof))
    }
}

fn vault_err(e: impl std::fmt::Display) -> EnrollError {
    EnrollError::Vault(e.to_string())
}

fn decode_fixed<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], EnrollError> {
    hex::decode(hex_str)
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v).ok())
        .ok_or_else(|| EnrollError::Vault(format!("{what} must be {N} hex-encoded bytes")))
}
