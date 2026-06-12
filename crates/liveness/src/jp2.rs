//! JPEG2000 decoding via the pure-Rust openjp2 backend of `jpeg2k`.
//! Accepts both raw codestreams and JP2 box containers (auto-detected).

use crate::{Error, Image};

/// Decode JPEG2000 bytes (e.g. `AadhaarRecord::photo_jp2`) into RGB8.
pub fn decode_jp2(bytes: &[u8]) -> Result<Image, Error> {
    let decoded = jpeg2k::Image::from_bytes(bytes).map_err(|e| Error::Jp2Decode(e.to_string()))?;
    let (width, height) = (decoded.width(), decoded.height());
    let pixels = (width as usize) * (height as usize);
    let components = decoded.components();

    for component in components {
        if component.width() != width || component.height() != height {
            return Err(Error::UnsupportedFormat(
                "subsampled components are not supported".into(),
            ));
        }
    }

    let to8 = |value: i32, precision: u32| -> u8 {
        let v = match precision {
            0..=7 => value << (8 - precision),
            8 => value,
            _ => value >> (precision - 8),
        };
        v.clamp(0, 255) as u8
    };

    let mut rgb = Vec::with_capacity(pixels * 3);
    match components {
        [gray] => {
            for &v in gray.data() {
                let v = to8(v, gray.precision());
                rgb.extend_from_slice(&[v, v, v]);
            }
        }
        // 4 components: alpha dropped.
        [r, g, b] | [r, g, b, _] => {
            for i in 0..pixels {
                rgb.push(to8(r.data()[i], r.precision()));
                rgb.push(to8(g.data()[i], g.precision()));
                rgb.push(to8(b.data()[i], b.precision()));
            }
        }
        other => {
            return Err(Error::UnsupportedFormat(format!(
                "{} components",
                other.len()
            )));
        }
    }

    Image::new(width, height, rgb)
}
