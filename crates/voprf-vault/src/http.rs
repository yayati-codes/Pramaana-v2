//! Minimal JSON-over-HTTP transport for O (feature `http-server`).
//!
//! Routes (all values hex-encoded):
//! - `GET  /pubkey`    → `{ "public_key": ... }`
//! - `POST /challenge` → `{ "nonce": ... }`
//! - `POST /evaluate`  `{ "nonce", "blinded", "quote" }` →
//!   `{ "evaluation", "proof" }`, or 4xx `{ "error": ... }`
//!
//! Deployment hardening (RA-TLS termination, dstack TLS certs) is layered on
//! top of this at deploy time; the gate checks themselves live in the vault.

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::JoinHandle;

use attestation::Verifier;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::{VaultError, VoprfVault, NONCE_LEN};

#[derive(Serialize)]
struct PubkeyResponse {
    public_key: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    nonce: String,
}

#[derive(Deserialize)]
struct EvaluateRequest {
    nonce: String,
    blinded: String,
    quote: String,
}

#[derive(Serialize)]
struct EvaluateResponse {
    evaluation: String,
    proof: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub struct VaultServer;

impl VaultServer {
    /// Serve `vault` on `addr` (use port 0 for an ephemeral port) in a
    /// background thread. Returns the bound address.
    pub fn spawn<V: Verifier + Send + Sync + 'static>(
        vault: Arc<VoprfVault<V>>,
        addr: &str,
    ) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
        let server = Server::http(addr).map_err(std::io::Error::other)?;
        let local = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| std::io::Error::other("non-IP listen address"))?;
        let handle = std::thread::spawn(move || {
            for request in server.incoming_requests() {
                handle_request(&vault, request);
            }
        });
        Ok((local, handle))
    }
}

fn handle_request<V: Verifier>(vault: &VoprfVault<V>, mut request: Request) {
    let (status, body) = match (request.method().clone(), request.url().to_owned()) {
        (Method::Get, url) if url == "/pubkey" => (
            200,
            serde_json::to_string(&PubkeyResponse {
                public_key: hex::encode(vault.public_key()),
            })
            .expect("serialize"),
        ),
        (Method::Post, url) if url == "/challenge" => (
            200,
            serde_json::to_string(&ChallengeResponse {
                nonce: hex::encode(vault.challenge()),
            })
            .expect("serialize"),
        ),
        (Method::Post, url) if url == "/evaluate" => {
            let mut raw = String::new();
            match request.as_reader().read_to_string(&mut raw) {
                Ok(_) => evaluate_route(vault, &raw),
                Err(e) => error_body(400, &format!("body read: {e}")),
            }
        }
        _ => error_body(404, "unknown route"),
    };

    let response = Response::from_string(body)
        .with_status_code(status)
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("header"),
        );
    let _ = request.respond(response);
}

fn evaluate_route<V: Verifier>(vault: &VoprfVault<V>, raw: &str) -> (u16, String) {
    let parsed: EvaluateRequest = match serde_json::from_str(raw) {
        Ok(p) => p,
        Err(e) => return error_body(400, &format!("bad json: {e}")),
    };
    let (Ok(nonce), Ok(blinded), Ok(quote)) = (
        hex::decode(&parsed.nonce),
        hex::decode(&parsed.blinded),
        hex::decode(&parsed.quote),
    ) else {
        return error_body(400, "fields must be hex");
    };
    let Ok(nonce): Result<[u8; NONCE_LEN], _> = nonce.try_into() else {
        return error_body(400, "nonce must be 32 bytes");
    };

    match vault.evaluate(&nonce, &blinded, &quote) {
        Ok(ok) => (
            200,
            serde_json::to_string(&EvaluateResponse {
                evaluation: hex::encode(ok.evaluation),
                proof: hex::encode(ok.proof),
            })
            .expect("serialize"),
        ),
        Err(e) => {
            let status = match e {
                VaultError::UnknownNonce => 409,
                VaultError::QuoteInvalid(_) | VaultError::NotBound => 403,
                VaultError::Voprf(_) => 422,
            };
            error_body(status, &e.to_string())
        }
    }
}

fn error_body(status: u16, message: &str) -> (u16, String) {
    (
        status,
        serde_json::to_string(&ErrorResponse {
            error: message.to_owned(),
        })
        .expect("serialize"),
    )
}
