use crate::{
    decode_jp2, verify_capture, CaptureMetadata, ChallengeNonce, Error, FaceMatcher, Image,
    LiveCapture, MatchScore, SimMatcher,
};

const W: u32 = 64;
const H: u32 = 64;

/// Synthetic "face": radial gradient centered at (cx, cy).
fn radial_face(cx: f32, cy: f32) -> Image {
    let mut rgb = Vec::with_capacity((W * H * 3) as usize);
    for y in 0..H {
        for x in 0..W {
            let d = ((x as f32 - cx).powi(2) + (y as f32 - cy).powi(2)).sqrt() / 28.0;
            let v = (255.0 * (1.0 - d).max(0.0)) as u8;
            rgb.extend_from_slice(&[v, v, v]);
        }
    }
    Image::new(W, H, rgb).unwrap()
}

/// A structurally different "person": vertical stripes.
fn stripes() -> Image {
    let mut rgb = Vec::with_capacity((W * H * 3) as usize);
    for _y in 0..H {
        for x in 0..W {
            let v = if (x / 8) % 2 == 0 { 230 } else { 25 };
            rgb.extend_from_slice(&[v, v, v]);
        }
    }
    Image::new(W, H, rgb).unwrap()
}

/// Deterministic per-pixel perturbation (re-capture of the same person).
fn noised(img: &Image) -> Image {
    let rgb = img
        .rgb()
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let delta = ((i * 31) % 7) as i16 - 3;
            (i16::from(v) + delta).clamp(0, 255) as u8
        })
        .collect();
    Image::new(img.width(), img.height(), rgb).unwrap()
}

#[test]
fn jp2_roundtrip_from_qr_generator() {
    // DoD: decode the photo that comes out of the aadhaar-qr test generator.
    let (sk, pk) = aadhaar_qr::testgen::generate_keypair();
    let qr = aadhaar_qr::testgen::generate_qr(&aadhaar_qr::testgen::TestQrSpec::default(), &sk);
    let record = aadhaar_qr::parse_and_verify(&qr, &pk).unwrap();

    let photo = decode_jp2(&record.photo_jp2).expect("QR photo must decode as JPEG2000");
    assert_eq!((photo.width(), photo.height()), (64, 64));
    assert_eq!(photo.rgb().len(), 64 * 64 * 3);
    // The synthetic face is brighter at its center than at the border.
    let center = photo.block_luma(28, 26, 36, 34);
    let corner = photo.block_luma(0, 0, 8, 8);
    assert!(center > corner + 50.0, "center {center} vs corner {corner}");
}

#[test]
fn sim_same_person_passes() {
    let matcher = SimMatcher::default();
    let person = radial_face(32.0, 30.0);

    let identical = matcher.match_faces(&person, &person).unwrap();
    assert!(identical.is_match());
    assert!(identical.score > 0.999);

    let recapture = matcher.match_faces(&noised(&person), &person).unwrap();
    assert!(recapture.is_match(), "noised score {}", recapture.score);
}

#[test]
fn sim_different_person_fails() {
    let matcher = SimMatcher::default();
    let result = matcher
        .match_faces(&stripes(), &radial_face(32.0, 30.0))
        .unwrap();
    assert!(!result.is_match(), "score {}", result.score);
}

#[test]
fn sim_threshold_is_configurable() {
    let person = radial_face(32.0, 30.0);
    let other = radial_face(10.0, 50.0);
    let score = SimMatcher::default().match_faces(&other, &person).unwrap();
    // A permissive matcher accepts what the default rejects.
    assert!(!score.is_match());
    let permissive = SimMatcher::new(0.1).match_faces(&other, &person).unwrap();
    assert!(permissive.is_match());
    // Boundary: score equal to threshold counts as a match.
    assert!(MatchScore {
        score: 0.5,
        threshold: 0.5
    }
    .is_match());
}

#[test]
fn liveness_nonce_echo() {
    let nonce = ChallengeNonce([7u8; 32]);
    let frame = radial_face(32.0, 30.0);
    let capture = |frames: Vec<Image>, echo: [u8; 32]| LiveCapture {
        frames,
        metadata: CaptureMetadata {
            nonce_echo: echo,
            captured_at_ms: 1_765_900_800_000,
        },
    };

    let ok = capture(vec![frame.clone(), noised(&frame)], [7u8; 32]);
    assert!(verify_capture(&ok, &nonce).is_ok());

    let replay = capture(vec![frame.clone(), noised(&frame)], [8u8; 32]);
    assert!(matches!(
        verify_capture(&replay, &nonce),
        Err(Error::NonceMismatch)
    ));

    let single_still = capture(vec![frame], [7u8; 32]);
    assert!(matches!(
        verify_capture(&single_still, &nonce),
        Err(Error::EmptyCapture)
    ));
}
