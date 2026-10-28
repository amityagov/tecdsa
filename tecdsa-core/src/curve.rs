//! Elliptic-curve helpers over secp256k1.
use alloc::vec::Vec;
use k256::{
    AffinePoint, ProjectivePoint, Scalar, Secp256k1, U256,
    elliptic_curve::{
        PrimeField,
        bigint::U512,
        group::{Group, GroupEncoding},
        ops::Reduce,
        point::AffineCoordinates,
    },
    hash2curve::GroupDigest,
};

use crate::error::{Error, Result};

/// Domain separation tag for `h` and `f` (spec §10.3).
pub const H2C_DST: &[u8] = b"tecdsa-1ole/v1/h2c/secp256k1_XMD:SHA-256_SSWU_RO_";

/// `𝒳(R)`: x-coordinate of an affine point reduced modulo the group order.
pub fn x_coord(point: &ProjectivePoint) -> Scalar {
    let x = point.to_affine().x();
    <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(x.as_slice()))
}

/// Hash-to-curve generators `h` and `f` bound to `sid` (spec §10.3).
pub fn derive_h_f(sid: &[u8]) -> Result<(ProjectivePoint, ProjectivePoint)> {
    let derive = |label: &[u8]| {
        Secp256k1::hash_from_bytes(&[label, sid], &[H2C_DST]).map_err(|_| Error::InvalidEncoding)
    };
    Ok((derive(b"h")?, derive(b"f")?))
}

/// 33-byte compressed SEC1 encoding.
pub fn encode_point(p: &ProjectivePoint) -> [u8; 33] {
    let mut out = [0u8; 33];
    out.copy_from_slice(p.to_affine().to_bytes().as_ref());
    out
}

/// Decodes a compressed point; rejects off-curve encodings and the identity.
pub fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    let arr: [u8; 33] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
    // Canonical form only: SEC1 also defines tags 0x00/0x04/0x05 which the decoder may accept.
    if arr[0] != 0x02 && arr[0] != 0x03 {
        return Err(Error::InvalidEncoding);
    }
    let p = Option::<AffinePoint>::from(AffinePoint::from_bytes(&arr.into()))
        .ok_or(Error::InvalidEncoding)?;
    let p = ProjectivePoint::from(p);
    if is_identity(&p) {
        return Err(Error::InvalidEncoding);
    }
    Ok(p)
}

/// 32-byte big-endian scalar encoding.
pub fn encode_scalar(s: &Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(s.to_repr().as_ref());
    out
}

/// Decodes a canonical scalar (< q).
pub fn decode_scalar(bytes: &[u8]) -> Result<Scalar> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
    Option::<Scalar>::from(Scalar::from_repr(arr.into())).ok_or(Error::InvalidEncoding)
}

/// Uniform non-zero scalar.
pub fn random_nonzero_scalar<R: k256::elliptic_curve::rand_core::TryRng + ?Sized>(
    rng: &mut R,
) -> Scalar {
    loop {
        let mut wide = Vec::from([0u8; 64]);
        if rng.try_fill_bytes(&mut wide).is_err() {
            continue;
        }
        let s = <Scalar as Reduce<U512>>::reduce(&U512::from_be_slice(&wide));
        if !bool::from(k256::elliptic_curve::Field::is_zero(&s)) {
            return s;
        }
    }
}

/// `true` for the group generator multiple that is not the identity.
pub fn is_identity(p: &ProjectivePoint) -> bool {
    bool::from(p.is_identity())
}

/// The group order `q` as an integer.
pub fn order() -> crypto_bigint::BoxedUint {
    use k256::elliptic_curve::Curve;
    let be = <Secp256k1 as Curve>::ORDER.to_be_bytes();
    crypto_bigint::BoxedUint::from_be_slice_vartime(be.as_ref())
}

/// Reduces a signed integer modulo `q` (constant-time in the value).
pub fn sbig_to_scalar(x: &crate::arith::sbig::SBig) -> Result<Scalar> {
    let q = Option::<crypto_bigint::NonZero<crypto_bigint::BoxedUint>>::from(order().to_nz())
        .ok_or(Error::InvalidModulus)?;
    let r = x.rem_euclid(&q);
    decode_scalar(&crate::transcript::uint_to_be(&r, 32)?)
}
