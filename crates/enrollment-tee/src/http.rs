//! Minimal JSON-over-HTTP transport for T (feature `http-server`), mirroring
//! voprf-vault's server. Routes:
//!
//! - `POST /handshake` `{ "nonce": hex }` →
//!   `{ "quote": hex, "ephemeral_pubkey": hex, "liveness_nonce": hex }`
//!   Gate 0 (§2 step 1) + a fresh liveness challenge, burned on use.
//! - `POST /enroll` `{ "liveness_nonce": hex, "qr_numeric": str,
//!   "capture": { "frames": [{ "width", "height", "rgb_b64" }],
//!   "nonce_echo": hex, "captured_at_ms": u64 } }` →
//!   `{ "phi": hex, "dedup_tag": hex, "already_enrolled": bool,
//!   "sk_idr": hex }` — sk_IdR crosses this channel ONCE (§3); RA-TLS
//!   termination is layered on at deployment (docs/DECISIONS.md).
//! - `GET /fixture` (feature `sim-fixture` only): synthetic signed QR +
//!   matching RGB capture frames so a demo client needs no QR/JP2 tooling.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use liveness::{CaptureMetadata, ChallengeNonce, FaceMatcher, Image, LiveCapture};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::registry::Registry;
use crate::{EnrollError, EnrollmentRequest, EnrollmentTee};

#[derive(Deserialize)]
struct HandshakeRequest {
    nonce: String,
}

#[derive(Serialize)]
struct HandshakeResponse {
    quote: String,
    ephemeral_pubkey: String,
    liveness_nonce: String,
}

#[derive(Serialize, Deserialize)]
struct FrameJson {
    width: u32,
    height: u32,
    rgb_b64: String,
}

#[derive(Deserialize)]
struct CaptureJson {
    frames: Vec<FrameJson>,
    nonce_echo: String,
    captured_at_ms: u64,
}

#[derive(Deserialize)]
struct EnrollRequestJson {
    liveness_nonce: String,
    qr_numeric: String,
    capture: CaptureJson,
}

#[derive(Serialize)]
struct EnrollResponseJson {
    phi: String,
    dedup_tag: String,
    already_enrolled: bool,
    sk_idr: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(feature = "sim-fixture")]
#[derive(Serialize)]
struct FixtureResponse {
    qr_numeric: String,
    frames: Vec<FrameJson>,
}

/// SIM-ONLY fixture material: the demo UIDAI signing key + the synthetic
/// person it signs for.
#[cfg(feature = "sim-fixture")]
pub struct FixtureState {
    pub spec: aadhaar_qr::testgen::TestQrSpec,
    pub signing_key: aadhaar_qr::RsaPrivateKey,
}

/// T behind the transport: the orchestrator plus the liveness-challenge
/// ledger (issued by /handshake, burned by /enroll — vault nonce pattern).
pub struct TeeService<M: FaceMatcher, R: Registry> {
    tee: EnrollmentTee<M, R>,
    issued_liveness_nonces: Mutex<HashSet<[u8; 32]>>,
    #[cfg(feature = "sim-fixture")]
    fixture: Option<FixtureState>,
}

impl<M: FaceMatcher, R: Registry> TeeService<M, R> {
    pub fn new(tee: EnrollmentTee<M, R>) -> Self {
        Self {
            tee,
            issued_liveness_nonces: Mutex::new(HashSet::new()),
            #[cfg(feature = "sim-fixture")]
            fixture: None,
        }
    }

    #[cfg(feature = "sim-fixture")]
    pub fn with_fixture(tee: EnrollmentTee<M, R>, fixture: FixtureState) -> Self {
        Self {
            tee,
            issued_liveness_nonces: Mutex::new(HashSet::new()),
            fixture: Some(fixture),
        }
    }
}

pub struct TeeServer;

impl TeeServer {
    /// Serve on `addr` (port 0 for ephemeral) in a background thread.
    pub fn spawn<M, R>(
        service: Arc<TeeService<M, R>>,
        addr: &str,
    ) -> std::io::Result<(SocketAddr, JoinHandle<()>)>
    where
        M: FaceMatcher + Send + Sync + 'static,
        R: Registry + Send + Sync + 'static,
    {
        let server = Server::http(addr).map_err(std::io::Error::other)?;
        let local = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| std::io::Error::other("non-IP listen address"))?;
        let handle = std::thread::spawn(move || {
            for request in server.incoming_requests() {
                handle_request(&service, request);
            }
        });
        Ok((local, handle))
    }
}

fn handle_request<M: FaceMatcher, R: Registry>(
    service: &TeeService<M, R>,
    mut request: Request,
) {
    let (status, body) = match (request.method().clone(), request.url().to_owned()) {
        (Method::Post, url) if url == "/handshake" => {
            match read_body(&mut request) {
                Ok(raw) => handshake_route(service, &raw),
                Err(e) => error_body(400, &e),
            }
        }
        (Method::Post, url) if url == "/enroll" => match read_body(&mut request) {
            Ok(raw) => enroll_route(service, &raw),
            Err(e) => error_body(400, &e),
        },
        #[cfg(feature = "sim-fixture")]
        (Method::Get, url) if url == "/fixture" => fixture_route(service),
        _ => error_body(404, "unknown route"),
    };

    let response = Response::from_string(body)
        .with_status_code(status)
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("header"),
        );
    let _ = request.respond(response);
}

fn read_body(request: &mut Request) -> Result<String, String> {
    let mut raw = String::new();
    request
        .as_reader()
        .read_to_string(&mut raw)
        .map_err(|e| format!("body read: {e}"))?;
    Ok(raw)
}

fn handshake_route<M: FaceMatcher, R: Registry>(
    service: &TeeService<M, R>,
    raw: &str,
) -> (u16, String) {
    let parsed: HandshakeRequest = match serde_json::from_str(raw) {
        Ok(p) => p,
        Err(e) => return error_body(400, &format!("bad json: {e}")),
    };
    let Ok(nonce) = hex::decode(&parsed.nonce) else {
        return error_body(400, "nonce must be hex");
    };

    let handshake = match service.tee.gate0_handshake(&nonce) {
        Ok(h) => h,
        Err(e) => return error_body(500, &e.to_string()),
    };

    let mut liveness_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut liveness_nonce);
    service
        .issued_liveness_nonces
        .lock()
        .expect("nonce ledger poisoned")
        .insert(liveness_nonce);

    (
        200,
        serde_json::to_string(&HandshakeResponse {
            quote: hex::encode(&handshake.quote),
            ephemeral_pubkey: hex::encode(handshake.ephemeral_pubkey),
            liveness_nonce: hex::encode(liveness_nonce),
        })
        .expect("serialize"),
    )
}

fn enroll_route<M: FaceMatcher, R: Registry>(
    service: &TeeService<M, R>,
    raw: &str,
) -> (u16, String) {
    let parsed: EnrollRequestJson = match serde_json::from_str(raw) {
        Ok(p) => p,
        Err(e) => return error_body(400, &format!("bad json: {e}")),
    };
    let (Ok(liveness_nonce), Ok(nonce_echo)) = (
        decode_hex32(&parsed.liveness_nonce),
        decode_hex32(&parsed.capture.nonce_echo),
    ) else {
        return error_body(400, "liveness_nonce/nonce_echo must be 32 hex-encoded bytes");
    };

    // Burn the challenge: it must have been issued by /handshake and is
    // single-use (a replayed capture cannot echo a fresh nonce).
    if !service
        .issued_liveness_nonces
        .lock()
        .expect("nonce ledger poisoned")
        .remove(&liveness_nonce)
    {
        return error_body(403, "unknown or already-used liveness nonce");
    }

    let mut frames = Vec::with_capacity(parsed.capture.frames.len());
    for frame in &parsed.capture.frames {
        let Ok(rgb) = B64.decode(&frame.rgb_b64) else {
            return error_body(400, "frame rgb_b64 is not valid base64");
        };
        match Image::new(frame.width, frame.height, rgb) {
            Ok(img) => frames.push(img),
            Err(e) => return error_body(400, &format!("bad frame: {e}")),
        }
    }

    let enrollment = EnrollmentRequest {
        qr_numeric: parsed.qr_numeric,
        live_capture: LiveCapture {
            frames,
            metadata: CaptureMetadata {
                nonce_echo,
                captured_at_ms: parsed.capture.captured_at_ms,
            },
        },
        liveness_nonce: ChallengeNonce(liveness_nonce),
    };

    match service.tee.enroll(enrollment) {
        Ok(out) => (
            200,
            serde_json::to_string(&EnrollResponseJson {
                phi: hex::encode(out.handle.phi),
                dedup_tag: hex::encode(out.handle.dedup_tag),
                already_enrolled: out.handle.already_enrolled,
                sk_idr: hex::encode(&*out.sk_idr),
            })
            .expect("serialize"),
        ),
        Err(e) => {
            let status = match e {
                EnrollError::Qr(_) | EnrollError::Liveness(_) | EnrollError::FaceMismatch { .. } => 403,
                EnrollError::Vault(_) | EnrollError::GateK(_) => 502,
                _ => 500,
            };
            error_body(status, &e.to_string())
        }
    }
}

#[cfg(feature = "sim-fixture")]
fn fixture_route<M: FaceMatcher, R: Registry>(service: &TeeService<M, R>) -> (u16, String) {
    let Some(fixture) = &service.fixture else {
        return error_body(404, "no fixture configured");
    };
    let qr_numeric = aadhaar_qr::testgen::generate_qr(&fixture.spec, &fixture.signing_key);
    // The "live capture" is the QR photo itself (same person), decoded
    // server-side so the client needs no JP2 tooling. MIN_FRAMES copies.
    let face = match liveness::decode_jp2(&fixture.spec.photo_jp2) {
        Ok(img) => img,
        Err(e) => return error_body(500, &format!("fixture photo: {e}")),
    };
    let frame = FrameJson {
        width: face.width(),
        height: face.height(),
        rgb_b64: B64.encode(face.rgb()),
    };
    let frames = vec![
        FrameJson {
            width: frame.width,
            height: frame.height,
            rgb_b64: frame.rgb_b64.clone(),
        },
        frame,
    ];
    (
        200,
        serde_json::to_string(&FixtureResponse { qr_numeric, frames }).expect("serialize"),
    )
}

fn decode_hex32(s: &str) -> Result<[u8; 32], ()> {
    let bytes = hex::decode(s).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
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
