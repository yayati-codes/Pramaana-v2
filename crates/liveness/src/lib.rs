//! Liveness + face match (ARCHITECTURE.md §2 step 5, §5).
//!
//! Decode the JP2 photo from the Secure QR, accept a live face capture, and
//! match the two INSIDE the enclave. The photo is for liveness only — it must
//! never feed key derivation (§4).
//!
//! Two [`FaceMatcher`] implementations behind cargo features:
//! - `sim` (default): deterministic perceptual-fingerprint matcher, no ML.
//! - `onnx`: real face-embedding model via ONNX Runtime (`ort`); cosine
//!   similarity of embeddings; needs an external model file.

mod capture;
mod jp2;
#[cfg(feature = "onnx")]
mod onnx;
#[cfg(feature = "sim")]
mod sim;

pub use capture::{verify_capture, CaptureMetadata, ChallengeNonce, LiveCapture};
pub use jp2::decode_jp2;
#[cfg(feature = "onnx")]
pub use onnx::{OnnxMatcher, DEFAULT_ONNX_THRESHOLD};
#[cfg(feature = "sim")]
pub use sim::SimMatcher;

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JPEG2000 decode failed: {0}")]
    Jp2Decode(String),
    #[error("unsupported image format: {0}")]
    UnsupportedFormat(String),
    #[error("image is empty or dimensions do not match buffer")]
    InvalidImage,
    #[error("capture has too few frames for a liveness check")]
    EmptyCapture,
    #[error("capture did not echo the challenge nonce (possible replay)")]
    NonceMismatch,
    #[cfg(feature = "onnx")]
    #[error("ONNX runtime error: {0}")]
    Onnx(String),
}

/// Minimal RGB8 image (row-major, 3 bytes/pixel). Face photos are PII:
/// zeroized on drop (§4).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Image {
    width: u32,
    height: u32,
    rgb: Vec<u8>,
}

impl Image {
    pub fn new(width: u32, height: u32, rgb: Vec<u8>) -> Result<Self, Error> {
        if width == 0 || height == 0 || rgb.len() != (width * height * 3) as usize {
            return Err(Error::InvalidImage);
        }
        Ok(Self { width, height, rgb })
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// Row-major RGB8 pixels.
    pub fn rgb(&self) -> &[u8] {
        &self.rgb
    }

    /// Mean luma (Rec. 601) of the pixels inside an axis-aligned block,
    /// used by the matchers' downscaling.
    pub(crate) fn block_luma(&self, x0: u32, y0: u32, x1: u32, y1: u32) -> f32 {
        let (mut sum, mut n) = (0.0f64, 0u64);
        for y in y0..y1.min(self.height) {
            for x in x0..x1.min(self.width) {
                let i = ((y * self.width + x) * 3) as usize;
                let [r, g, b] = [self.rgb[i], self.rgb[i + 1], self.rgb[i + 2]];
                sum += 0.299 * f64::from(r) + 0.587 * f64::from(g) + 0.114 * f64::from(b);
                n += 1;
            }
        }
        if n == 0 {
            0.0
        } else {
            (sum / n as f64) as f32
        }
    }
}

/// Outcome of a face match. `score` is in [0, 1]; the pair is accepted iff
/// `score >= threshold`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchScore {
    pub score: f32,
    pub threshold: f32,
}

impl MatchScore {
    pub fn is_match(&self) -> bool {
        self.score >= self.threshold
    }
}

/// Matches a live capture frame against the reference photo from the QR.
pub trait FaceMatcher {
    fn match_faces(&self, live: &Image, reference: &Image) -> Result<MatchScore, Error>;
}

#[cfg(test)]
mod tests;
