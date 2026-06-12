//! Deterministic non-ML matcher (default `sim` feature, ARCHITECTURE.md §6
//! spirit): lets the demo and tests run identically everywhere with no model.
//!
//! Fingerprint: 8x8 grid of block-mean lumas, mean-centered and L2-normalized;
//! score = cosine similarity mapped to [0, 1]. Identical or lightly-noised
//! images score ~1.0; structurally different images fall well below any
//! sensible threshold. This is a stand-in for face recognition, not a face
//! recognizer — the `onnx` feature provides the real thing.

use crate::{Error, FaceMatcher, Image, MatchScore};

const GRID: u32 = 8;
const DEFAULT_THRESHOLD: f32 = 0.90;

pub struct SimMatcher {
    threshold: f32,
}

impl SimMatcher {
    pub fn new(threshold: f32) -> Self {
        Self { threshold }
    }
}

impl Default for SimMatcher {
    fn default() -> Self {
        Self::new(DEFAULT_THRESHOLD)
    }
}

fn fingerprint(img: &Image) -> [f32; (GRID * GRID) as usize] {
    let mut cells = [0.0f32; (GRID * GRID) as usize];
    for gy in 0..GRID {
        for gx in 0..GRID {
            let x0 = gx * img.width() / GRID;
            let x1 = (gx + 1) * img.width() / GRID;
            let y0 = gy * img.height() / GRID;
            let y1 = (gy + 1) * img.height() / GRID;
            cells[(gy * GRID + gx) as usize] =
                img.block_luma(x0, y0, x1.max(x0 + 1), y1.max(y0 + 1));
        }
    }
    let mean = cells.iter().sum::<f32>() / cells.len() as f32;
    for c in &mut cells {
        *c -= mean;
    }
    let norm = cells.iter().map(|c| c * c).sum::<f32>().sqrt();
    if norm > f32::EPSILON {
        for c in &mut cells {
            *c /= norm;
        }
    }
    cells
}

impl FaceMatcher for SimMatcher {
    fn match_faces(&self, live: &Image, reference: &Image) -> Result<MatchScore, Error> {
        let (a, b) = (fingerprint(live), fingerprint(reference));
        let cosine: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        Ok(MatchScore {
            score: ((cosine + 1.0) / 2.0).clamp(0.0, 1.0),
            threshold: self.threshold,
        })
    }
}
