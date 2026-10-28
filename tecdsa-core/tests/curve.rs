//! Curve helper checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use k256::{ProjectivePoint, Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tecdsa_core::curve::*;

#[test]
fn x_coord_of_generator_is_gx_mod_q() {
    // Gx < q for secp256k1, so the reduction is the identity.
    let gx = decode_scalar(&hex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ))
    .unwrap();
    assert_eq!(x_coord(&ProjectivePoint::GENERATOR), gx);
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn point_and_scalar_encoding() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for _ in 0..50 {
        let k = random_nonzero_scalar(&mut rng);
        let p = ProjectivePoint::GENERATOR * k;
        assert_eq!(decode_point(&encode_point(&p)).unwrap(), p);
        assert_eq!(decode_scalar(&encode_scalar(&k)).unwrap(), k);
    }
    // identity, wrong length, off-curve prefix, non-canonical scalar
    assert!(decode_point(&[0u8; 33]).is_err());
    assert!(decode_point(&[2u8; 32]).is_err());
    let mut bad = encode_point(&ProjectivePoint::GENERATOR);
    for tag in [0u8, 1, 4, 5, 6, 7] {
        bad[0] = tag;
        assert!(decode_point(&bad).is_err(), "tag {tag}");
    }
    assert!(decode_scalar(&[0xffu8; 32]).is_err());
    assert!(decode_scalar(&[0u8; 31]).is_err());
    assert!(!bool::from(random_nonzero_scalar(&mut rng).is_zero()));
    let _ = Scalar::ONE;
}

#[test]
fn h_and_f_are_deterministic_and_independent() {
    let (h1, f1) = derive_h_f(b"sid-1").unwrap();
    let (h1b, f1b) = derive_h_f(b"sid-1").unwrap();
    let (h2, _) = derive_h_f(b"sid-2").unwrap();
    assert_eq!((h1, f1), (h1b, f1b));
    assert_ne!(h1, f1);
    assert_ne!(h1, h2);
    assert_ne!(h1, ProjectivePoint::GENERATOR);
    assert!(!is_identity(&h1) && !is_identity(&f1));
}
