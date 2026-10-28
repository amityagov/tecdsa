//! Π_dlog (paper Protocol 5.13): proof of knowledge of `x` with `X = g^x` on secp256k1.
//!
//! Compact Fiat–Shamir form `(e, z)`; the verifier reconstructs `A = g^z · X^{-e}`.
use alloc::vec::Vec;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRng;

use crate::{
    arith::sbig::{SBig, SRange},
    curve::{decode_scalar, encode_point, encode_scalar, is_identity, random_nonzero_scalar},
    error::{Error, Result},
    params::Params,
    transcript::{Challenge, Transcript, uint_to_be},
};

/// Compact proof `(e, z)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlogProof {
    pub e: SBig,
    pub z: Scalar,
}

/// Signed challenge as a scalar mod q (`|e| ≤ 2^{ℓ−1} < q` is required).
fn sbig_to_scalar(e: &SBig) -> Result<Scalar> {
    let bytes = uint_to_be(e.mag(), 32)?;
    let s = decode_scalar(&bytes)?;
    Ok(if bool::from(e.is_neg()) { -s } else { s })
}

fn base(tx: &Transcript, x_pub: &ProjectivePoint) -> Transcript {
    let mut t = tx.clone();
    t.append("zk", b"dlog");
    t.append("X", &encode_point(x_pub));
    t
}

fn derive_e(t: &Transcript, a: &ProjectivePoint, params: &Params) -> SBig {
    let mut t = t.clone();
    t.append("A", &encode_point(a));
    let mut ch: Challenge = t.challenge("e");
    ch.pm_pow2(params.ell)
}

fn e_range(params: &Params) -> SRange {
    SRange::pm_pow2(params.ell)
}

impl DlogProof {
    /// Proves knowledge of `x` with `X = g^x`.
    pub fn prove<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        x_pub: &ProjectivePoint,
        x: &Scalar,
    ) -> Result<Self> {
        if params.ell == 0 || params.ell > 255 || is_identity(x_pub) {
            return Err(Error::OutOfRange);
        }
        let t = base(tx, x_pub);
        let alpha = random_nonzero_scalar(rng);
        let a = ProjectivePoint::GENERATOR * alpha;
        let e = derive_e(&t, &a, params);
        let z = alpha + sbig_to_scalar(&e)? * x;
        Ok(Self { e, z })
    }

    /// Verifies the proof for `X`.
    pub fn verify(&self, tx: &Transcript, params: &Params, x_pub: &ProjectivePoint) -> Result<()> {
        if params.ell == 0 || params.ell > 255 || is_identity(x_pub) {
            return Err(Error::VerificationFailed);
        }
        if !self.e.in_range(e_range(params)) {
            return Err(Error::OutOfRange);
        }
        let es = sbig_to_scalar(&self.e)?;
        // A = g^z · X^{-e}
        let a = ProjectivePoint::GENERATOR * self.z - *x_pub * es;
        if is_identity(&a) {
            return Err(Error::VerificationFailed);
        }
        let t = base(tx, x_pub);
        if derive_e(&t, &a, params) == self.e {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    /// `e` (sign byte + ⌈(ℓ−1)/8⌉ bytes) ‖ `z` (32 bytes).
    pub fn encode(&self, params: &Params) -> Result<Vec<u8>> {
        let mut out = self.e.to_bytes(e_range(params))?;
        out.extend_from_slice(&encode_scalar(&self.z));
        Ok(out)
    }

    pub fn encoded_len(params: &Params) -> usize {
        1 + (params.ell.saturating_sub(1) as usize).div_ceil(8).max(1) + 32
    }

    pub fn decode(bytes: &[u8], params: &Params) -> Result<Self> {
        if bytes.len() != Self::encoded_len(params) {
            return Err(Error::InvalidEncoding);
        }
        let (eb, zb) = bytes.split_at(bytes.len() - 32);
        let e = SBig::from_bytes(eb, e_range(params))?;
        let z = decode_scalar(zb)?;
        Ok(Self { e, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PARAMS_128;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn setup() -> (ChaCha8Rng, Transcript, ProjectivePoint, Scalar) {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let x = random_nonzero_scalar(&mut rng);
        (
            rng,
            Transcript::new("test"),
            ProjectivePoint::GENERATOR * x,
            x,
        )
    }

    #[test]
    fn honest_and_roundtrip() {
        let (mut rng, tx, xp, x) = setup();
        let p = DlogProof::prove(&mut rng, &tx, &PARAMS_128, &xp, &x).unwrap();
        p.verify(&tx, &PARAMS_128, &xp).unwrap();
        let enc = p.encode(&PARAMS_128).unwrap();
        assert_eq!(enc.len(), 17 + 32);
        let q = DlogProof::decode(&enc, &PARAMS_128).unwrap();
        assert_eq!(p, q);
        q.verify(&tx, &PARAMS_128, &xp).unwrap();
        assert!(DlogProof::decode(&enc[1..], &PARAMS_128).is_err());
        let mut longer = enc.clone();
        longer.push(0);
        assert!(DlogProof::decode(&longer, &PARAMS_128).is_err());
    }

    #[test]
    fn many_seeds() {
        let (mut rng, tx, xp, x) = setup();
        for _ in 0..50 {
            let p = DlogProof::prove(&mut rng, &tx, &PARAMS_128, &xp, &x).unwrap();
            p.verify(&tx, &PARAMS_128, &xp).unwrap();
        }
    }

    #[test]
    fn tampering_fails() {
        let (mut rng, tx, xp, x) = setup();
        let p = DlogProof::prove(&mut rng, &tx, &PARAMS_128, &xp, &x).unwrap();
        // z
        let mut b = p.clone();
        b.z += Scalar::ONE;
        assert!(b.verify(&tx, &PARAMS_128, &xp).is_err());
        // e ± 1
        for d in [1i64, -1] {
            let mut b = p.clone();
            b.e = b.e.add(&SBig::from_i64(d));
            assert!(b.verify(&tx, &PARAMS_128, &xp).is_err());
        }
        // e out of range
        let mut b = p.clone();
        b.e = SBig::from_i64(1).add(&SBig::from_uint(
            crypto_bigint::BoxedUint::one_with_precision(192).shl(127),
        ));
        assert_eq!(b.verify(&tx, &PARAMS_128, &xp), Err(Error::OutOfRange));
        // statement
        let other = xp + ProjectivePoint::GENERATOR;
        assert!(p.verify(&tx, &PARAMS_128, &other).is_err());
        assert!(
            p.verify(&tx, &PARAMS_128, &ProjectivePoint::IDENTITY)
                .is_err()
        );
        // transcript
        let mut tx2 = Transcript::new("test");
        tx2.append("x", b"y");
        assert!(p.verify(&tx2, &PARAMS_128, &xp).is_err());
    }

    #[test]
    fn wrong_witness_fails() {
        let (mut rng, tx, xp, x) = setup();
        let p = DlogProof::prove(&mut rng, &tx, &PARAMS_128, &xp, &(x + Scalar::ONE)).unwrap();
        assert!(p.verify(&tx, &PARAMS_128, &xp).is_err());
    }

    #[test]
    fn decode_rejects_noncanonical() {
        let (mut rng, tx, xp, x) = setup();
        let p = DlogProof::prove(&mut rng, &tx, &PARAMS_128, &xp, &x).unwrap();
        let enc = p.encode(&PARAMS_128).unwrap();
        // z ≥ q
        let mut b = enc.clone();
        for v in b[17..].iter_mut() {
            *v = 0xff;
        }
        assert!(DlogProof::decode(&b, &PARAMS_128).is_err());
        // bad sign byte
        let mut b = enc.clone();
        b[0] = 2;
        assert!(DlogProof::decode(&b, &PARAMS_128).is_err());
        // negative zero
        let mut b = enc.clone();
        b[0] = 1;
        for v in b[1..17].iter_mut() {
            *v = 0;
        }
        assert!(DlogProof::decode(&b, &PARAMS_128).is_err());
        // e magnitude above 2^{ℓ−1}
        let mut b = enc.clone();
        b[0] = 0;
        b[1] = 0xff;
        assert!(DlogProof::decode(&b, &PARAMS_128).is_err());
    }
}
