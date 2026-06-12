//! Liveness-capture acceptance: a minimal but PRESENT anti-replay gate
//! (ARCHITECTURE.md §2 step 3/5). This is a stub: it enforces challenge
//! freshness, not anti-spoofing — real presentation-attack detection comes
//! with the `onnx` pipeline work.

use crate::{Error, Image};

/// Minimum frames for a "short capture" — a single still is trivially a photo
/// replay.
pub const MIN_FRAMES: usize = 2;

/// Fresh per-enrollment challenge issued by the verifier (T).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChallengeNonce(pub [u8; 32]);

pub struct CaptureMetadata {
    /// The challenge nonce the capturing client embedded in the capture.
    pub nonce_echo: [u8; 32],
    /// Client-reported capture time (informational; not trusted).
    pub captured_at_ms: u64,
}

pub struct LiveCapture {
    pub frames: Vec<Image>,
    pub metadata: CaptureMetadata,
}

/// Accept a capture iff it has enough frames and echoes the expected
/// challenge nonce (anti-replay: a pre-recorded capture cannot contain a
/// nonce issued after it was made).
pub fn verify_capture(capture: &LiveCapture, expected: &ChallengeNonce) -> Result<(), Error> {
    if capture.frames.len() < MIN_FRAMES {
        return Err(Error::EmptyCapture);
    }
    // Stub gate: plain comparison. The nonce is single-use and not secret
    // material, so constant-time comparison is not load-bearing here.
    if capture.metadata.nonce_echo != expected.0 {
        return Err(Error::NonceMismatch);
    }
    Ok(())
}
