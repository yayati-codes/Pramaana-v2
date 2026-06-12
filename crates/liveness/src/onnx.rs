//! Real face-embedding matcher via ONNX Runtime (`onnx` feature).
//!
//! Loads any face-embedding model (ArcFace/MobileFaceNet-style: NCHW float
//! input, single embedding output), embeds both images, and gates on cosine
//! similarity. No model ships with the repo; pass a path at construction.

use std::path::Path;
use std::sync::Mutex;

use ort::session::Session;
use ort::value::{Tensor, ValueType};

use crate::{Error, FaceMatcher, Image, MatchScore};

/// Mapped-cosine threshold (same [0, 1] scale as [`MatchScore`]). The common
/// ArcFace raw-cosine threshold 0.36 maps to (0.36 + 1) / 2 = 0.68.
pub const DEFAULT_ONNX_THRESHOLD: f32 = 0.68;

pub struct OnnxMatcher {
    /// `Session::run` needs `&mut`; Mutex keeps `FaceMatcher` usable by `&self`.
    session: Mutex<Session>,
    threshold: f32,
    input_width: u32,
    input_height: u32,
}

fn ort_err(e: ort::Error) -> Error {
    Error::Onnx(e.to_string())
}

impl OnnxMatcher {
    pub fn from_model_file(model: impl AsRef<Path>, threshold: f32) -> Result<Self, Error> {
        let session = Session::builder()
            .map_err(ort_err)?
            .commit_from_file(model)
            .map_err(ort_err)?;

        // Read static NCHW input dims from model metadata; default 112x112
        // when dynamic.
        let (mut input_width, mut input_height) = (112u32, 112u32);
        if let Some(input) = session.inputs().first() {
            if let ValueType::Tensor { shape, .. } = input.dtype() {
                if let [_, _, h, w] = shape[..] {
                    if h > 0 && w > 0 {
                        input_height = h as u32;
                        input_width = w as u32;
                    }
                }
            }
        }

        Ok(Self {
            session: Mutex::new(session),
            threshold,
            input_width,
            input_height,
        })
    }

    fn embed(&self, image: &Image) -> Result<Vec<f32>, Error> {
        let data = preprocess(image, self.input_width, self.input_height);
        let tensor = Tensor::from_array((
            [
                1usize,
                3,
                self.input_height as usize,
                self.input_width as usize,
            ],
            data,
        ))
        .map_err(ort_err)?;

        let mut session = self.session.lock().expect("ONNX session poisoned");
        let outputs = session.run(ort::inputs![tensor]).map_err(ort_err)?;
        let (_, embedding) = outputs[0].try_extract_tensor::<f32>().map_err(ort_err)?;
        Ok(embedding.to_vec())
    }
}

impl FaceMatcher for OnnxMatcher {
    fn match_faces(&self, live: &Image, reference: &Image) -> Result<MatchScore, Error> {
        let (a, b) = (self.embed(live)?, self.embed(reference)?);
        Ok(MatchScore {
            score: ((cosine(&a, &b) + 1.0) / 2.0).clamp(0.0, 1.0),
            threshold: self.threshold,
        })
    }
}

/// Bilinear resize to (w, h), NCHW layout, ArcFace-style normalization
/// (px - 127.5) / 128.
fn preprocess(image: &Image, w: u32, h: u32) -> Vec<f32> {
    let mut out = vec![0.0f32; 3 * (w as usize) * (h as usize)];
    let plane = (w as usize) * (h as usize);
    for y in 0..h {
        for x in 0..w {
            let px = bilinear(image, x, y, w, h);
            for c in 0..3 {
                out[c * plane + (y as usize) * (w as usize) + (x as usize)] =
                    (px[c] - 127.5) / 128.0;
            }
        }
    }
    out
}

fn bilinear(image: &Image, dx: u32, dy: u32, dst_w: u32, dst_h: u32) -> [f32; 3] {
    let sx = (dx as f32 + 0.5) * image.width() as f32 / dst_w as f32 - 0.5;
    let sy = (dy as f32 + 0.5) * image.height() as f32 / dst_h as f32 - 0.5;
    let x0 = sx.floor().max(0.0) as u32;
    let y0 = sy.floor().max(0.0) as u32;
    let x1 = (x0 + 1).min(image.width() - 1);
    let y1 = (y0 + 1).min(image.height() - 1);
    let (fx, fy) = (sx - x0 as f32, sy - y0 as f32);
    let (fx, fy) = (fx.clamp(0.0, 1.0), fy.clamp(0.0, 1.0));

    let at = |x: u32, y: u32, c: usize| -> f32 {
        f32::from(image.rgb()[((y * image.width() + x) * 3) as usize + c])
    };
    core::array::from_fn(|c| {
        let top = at(x0, y0, c) * (1.0 - fx) + at(x1, y0, c) * fx;
        let bottom = at(x0, y1, c) * (1.0 - fx) + at(x1, y1, c) * fx;
        top * (1.0 - fy) + bottom * fy
    })
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let dot: f32 = (0..n).map(|i| a[i] * b[i]).sum();
    let na: f32 = a[..n].iter().map(|v| v * v).sum::<f32>().sqrt();
    let nb: f32 = b[..n].iter().map(|v| v * v).sum::<f32>().sqrt();
    if na <= f32::EPSILON || nb <= f32::EPSILON {
        return 0.0;
    }
    dot / (na * nb)
}
