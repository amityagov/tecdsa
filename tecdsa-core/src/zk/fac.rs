//! Π_fac (paper Protocol 4): `N = p·q` with `p, q` of about `n/2` bits, proven in the
//! range-proof group `QR_d` for a public strong prime `d`.
//!
//! Compact Fiat–Shamir form `(P̃, Q̃, e, z1, z2, λ1, λ2, w)`; the verifier reconstructs
//! `Ã = g^{z1} h^{λ1} P̃^{-e}`, `B̃ = g^{z2} h^{λ2} Q̃^{-e}`, `C̃ = Q̃^{z1} h^{w} g^{-N e}`.
use alloc::vec::Vec;
use crypto_bigint::{BoxedUint, ConcatenatingMul, NonZero};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::{
    arith::{
        monty::{Modulus, Residue},
        multiexp::multiexp_vartime,
        sbig::{SBig, SRange, resized},
    },
    error::{Error, Result},
    params::Params,
    transcript::{Transcript, uint_from_be, uint_to_be},
};
use crypto_bigint::RandomMod;

/// Big-endian bytes of `d = 2^3459 + 1169115` (spec §5, row "d (Π_fac)").
const fn d_standard() -> [u8; 433] {
    let mut b = [0u8; 433];
    b[0] = 0x08; // 2^3459 = 2^3 · 2^(8·432)
    b[430] = 0x11; // 1169115 = 0x11D6DB
    b[431] = 0xD6;
    b[432] = 0xDB;
    b
}
pub const D_STANDARD_BE: [u8; 433] = d_standard();

/// Maximum number of restarts when a response falls outside its range (probability ≈ 2^-ν).
const MAX_ATTEMPTS: u32 = 64;

/// Public group parameters: the strong prime `d` (`(d−1)/2` prime as well).
#[derive(Clone, Debug)]
pub struct FacParams {
    d: Modulus,
    d_val: BoxedUint,
    half: NonZero<BoxedUint>,
    d_len: usize,
}

impl FacParams {
    /// `d` must be odd and larger than 5; strongness is the caller's responsibility.
    pub fn new(d: BoxedUint) -> Result<Self> {
        if d.bits() < 4 {
            return Err(Error::InvalidModulus);
        }
        let half = d
            .wrapping_sub(BoxedUint::one_with_precision(d.bits_precision()))
            .shr_vartime(1)
            .ok_or(Error::InvalidModulus)?;
        let half = Option::<NonZero<BoxedUint>>::from(half.to_nz()).ok_or(Error::InvalidModulus)?;
        Ok(Self {
            d_len: (d.bits() as usize).div_ceil(8),
            d: Modulus::new(d.clone())?,
            d_val: d,
            half,
        })
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        Self::new(uint_from_be(bytes, bytes.len() as u32 * 8)?)
    }

    /// The fixed `d = 2^3459 + 1169115` of both profiles.
    pub fn standard() -> Result<Self> {
        Self::from_be_bytes(&D_STANDARD_BE)
    }

    pub fn d(&self) -> &BoxedUint {
        &self.d_val
    }

    /// Generators `g, h ∈ QR_d` derived from the base transcript and `d`.
    fn gens(&self, tx: &Transcript) -> Result<(Residue, Residue)> {
        let mut t = tx.clone();
        t.append_uint("d", &self.d_val, self.d_len)?;
        let mut ch = t.challenge("zk/fac/gen");
        let g = ch.qr_mod(&self.d)?;
        let h = ch.qr_mod(&self.d)?;
        Ok((g, h))
    }

    fn check_size(&self, params: &Params, n_bits: u32) -> Result<()> {
        if self.d_val.bits() < n_bits + 2 * params.ell + 2 * params.nu + 4 {
            return Err(Error::InvalidModulus);
        }
        Ok(())
    }
}

/// Secret input `N = p·q`.
pub struct FacWitness<'a> {
    pub p: &'a BoxedUint,
    pub q: &'a BoxedUint,
}

/// Compact proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FacProof {
    pub p_tilde: BoxedUint,
    pub q_tilde: BoxedUint,
    pub e: SBig,
    pub z1: SBig,
    pub z2: SBig,
    pub lambda1: BoxedUint,
    pub lambda2: BoxedUint,
    pub w: BoxedUint,
}

/// Range of `z1, z2`: `±2^{n/2+ℓ+ν}`.
fn z_range(params: &Params, n_bits: u32) -> SRange {
    SRange::pm_pow2(n_bits.div_ceil(2) + params.ell + params.nu)
}

fn e_range(params: &Params) -> SRange {
    SRange::pm_pow2(params.ell)
}

fn sbig_len(r: SRange) -> usize {
    1 + (r.bits().saturating_sub(1) as usize).div_ceil(8).max(1)
}

/// Transcript up to (and including) the statement; first message is appended by `derive_e`.
fn base(
    tx: &Transcript,
    fp: &FacParams,
    n: &BoxedUint,
    g: &Residue,
    h: &Residue,
) -> Result<Transcript> {
    let mut t = tx.clone();
    t.append("zk", b"fac");
    t.append_uint("N", n, (n.bits() as usize).div_ceil(8))?;
    t.append_uint("d", &fp.d_val, fp.d_len)?;
    t.append_residue("g", &fp.d, g)?;
    t.append_residue("h", &fp.d, h)?;
    Ok(t)
}

struct First<'a> {
    p: &'a Residue,
    q: &'a Residue,
    a: &'a Residue,
    b: &'a Residue,
    c: &'a Residue,
}

fn derive_e(mut t: Transcript, fp: &FacParams, f: &First<'_>, params: &Params) -> Result<SBig> {
    t.append_residue("P", &fp.d, f.p)?;
    t.append_residue("Q", &fp.d, f.q)?;
    t.append_residue("A", &fp.d, f.a)?;
    t.append_residue("B", &fp.d, f.b)?;
    t.append_residue("C", &fp.d, f.c)?;
    Ok(t.challenge("e").pm_pow2(params.ell))
}

fn rand_half<R: CryptoRng + ?Sized>(rng: &mut R, fp: &FacParams) -> SBig {
    SBig::from_uint(BoxedUint::random_mod_vartime(rng, &fp.half))
}

impl FacProof {
    pub fn prove<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        fp: &FacParams,
        n: &BoxedUint,
        wit: &FacWitness<'_>,
    ) -> Result<Self> {
        Self::prove_inner(rng, tx, params, fp, n, wit, true)
    }

    fn prove_inner<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        fp: &FacParams,
        n: &BoxedUint,
        wit: &FacWitness<'_>,
        enforce: bool,
    ) -> Result<Self> {
        let nb = n.bits();
        fp.check_size(params, nb)?;
        if enforce {
            let prod = wit.p.concatenating_mul(wit.q);
            if resized(&prod, n.bits_precision()) != resized(n, prod.bits_precision()) {
                return Err(Error::InvalidModulus);
            }
        }
        let (g, h) = fp.gens(tx)?;
        let m = &fp.d;
        let half_bits = fp.half.bits();
        let zr = z_range(params, nb);
        let t = base(tx, fp, n, &g, &h)?;
        let mut p_s = SBig::from_uint(wit.p.clone());
        let mut q_s = SBig::from_uint(wit.q.clone());
        let p_bits = wit.p.bits().max(wit.q.bits());

        for _ in 0..MAX_ATTEMPTS {
            let mut r = rand_half(rng, fp);
            let mut s = rand_half(rng, fp);
            let p_t = m
                .pow_ct(&g, &p_s, p_bits)?
                .mul(&m.pow_ct(&h, &r, half_bits)?);
            let q_t = m
                .pow_ct(&g, &q_s, p_bits)?
                .mul(&m.pow_ct(&h, &s, half_bits)?);
            let mut alpha = SBig::random_in(rng, zr);
            let mut beta = SBig::random_in(rng, zr);
            let mut rho = rand_half(rng, fp);
            let mut sigma = rand_half(rng, fp);
            let mut mu = rand_half(rng, fp);
            let a = m
                .pow_ct(&g, &alpha, zr.bits())?
                .mul(&m.pow_ct(&h, &rho, half_bits)?);
            let b = m
                .pow_ct(&g, &beta, zr.bits())?
                .mul(&m.pow_ct(&h, &sigma, half_bits)?);
            let c = m
                .pow_ct(&q_t, &alpha, zr.bits())?
                .mul(&m.pow_ct(&h, &mu, half_bits)?);
            let e = derive_e(
                t.clone(),
                fp,
                &First {
                    p: &p_t,
                    q: &q_t,
                    a: &a,
                    b: &b,
                    c: &c,
                },
                params,
            )?;
            let z1 = alpha.add(&e.mul(&p_s));
            let z2 = beta.add(&e.mul(&q_s));
            let lam1 = rho.add(&e.mul(&r)).rem_euclid(&fp.half);
            let lam2 = sigma.add(&e.mul(&s)).rem_euclid(&fp.half);
            let w = mu.add(&e.mul(&s.mul(&p_s).negate())).rem_euclid(&fp.half);
            for v in [
                &mut r, &mut s, &mut alpha, &mut beta, &mut rho, &mut sigma, &mut mu,
            ] {
                v.zeroize();
            }
            if enforce && !(z1.in_range(zr) && z2.in_range(zr)) {
                continue;
            }
            p_s.zeroize();
            q_s.zeroize();
            return Ok(Self {
                p_tilde: p_t.retrieve(),
                q_tilde: q_t.retrieve(),
                e,
                z1,
                z2,
                lambda1: lam1,
                lambda2: lam2,
                w,
            });
        }
        p_s.zeroize();
        q_s.zeroize();
        Err(Error::OutOfRange)
    }

    /// `0 < x < d` and `x` a quadratic residue (Jacobi symbol 1; `d` is prime).
    fn member(fp: &FacParams, x: &BoxedUint) -> Result<Residue> {
        let xr = resized(x, fp.d_val.bits_precision());
        if bool::from(xr.is_zero())
            || xr.cmp_vartime(resized(&fp.d_val, xr.bits_precision())) != core::cmp::Ordering::Less
        {
            return Err(Error::VerificationFailed);
        }
        if fp.d.jacobi_vartime(&xr) != 1 {
            return Err(Error::VerificationFailed);
        }
        Ok(fp.d.residue(&xr))
    }

    pub fn verify(
        &self,
        tx: &Transcript,
        params: &Params,
        fp: &FacParams,
        n: &BoxedUint,
    ) -> Result<()> {
        let fail = Error::VerificationFailed;
        let nb = n.bits();
        fp.check_size(params, nb).map_err(|_| fail)?;
        let zr = z_range(params, nb);
        if !self.z1.in_range(zr) || !self.z2.in_range(zr) || !self.e.in_range(e_range(params)) {
            return Err(fail);
        }
        for v in [&self.lambda1, &self.lambda2, &self.w] {
            let v = resized(v, fp.half.bits_precision());
            if v.cmp_vartime(resized(fp.half.as_ref(), v.bits_precision()))
                != core::cmp::Ordering::Less
            {
                return Err(fail);
            }
        }
        let p_t = Self::member(fp, &self.p_tilde)?;
        let q_t = Self::member(fp, &self.q_tilde)?;
        let (g, h) = fp.gens(tx).map_err(|_| fail)?;
        let m = &fp.d;
        let neg_e = self.e.negate();
        let l1 = SBig::from_uint(self.lambda1.clone());
        let l2 = SBig::from_uint(self.lambda2.clone());
        let ws = SBig::from_uint(self.w.clone());
        let a = multiexp_vartime(m, &[(&g, &self.z1), (&h, &l1), (&p_t, &neg_e)])?;
        let b = multiexp_vartime(m, &[(&g, &self.z2), (&h, &l2), (&q_t, &neg_e)])?;
        let ne = SBig::from_uint(n.clone()).mul(&self.e).negate();
        let c = multiexp_vartime(m, &[(&q_t, &self.z1), (&h, &ws), (&g, &ne)])?;
        let t = base(tx, fp, n, &g, &h)?;
        let e = derive_e(
            t,
            fp,
            &First {
                p: &p_t,
                q: &q_t,
                a: &a,
                b: &b,
                c: &c,
            },
            params,
        )?;
        if e == self.e { Ok(()) } else { Err(fail) }
    }

    /// Length of the encoding: `P̃, Q̃` (`⌈bits(d)/8⌉` each), `e`, `z1`, `z2` (§10.2), `λ1, λ2, w`.
    pub fn encoded_len(params: &Params, fp: &FacParams, n_bits: u32) -> usize {
        5 * fp.d_len + sbig_len(e_range(params)) + 2 * sbig_len(z_range(params, n_bits))
    }

    pub fn encode(&self, params: &Params, fp: &FacParams, n_bits: u32) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::encoded_len(params, fp, n_bits));
        out.extend_from_slice(&uint_to_be(&self.p_tilde, fp.d_len)?);
        out.extend_from_slice(&uint_to_be(&self.q_tilde, fp.d_len)?);
        out.extend_from_slice(&self.e.to_bytes(e_range(params))?);
        out.extend_from_slice(&self.z1.to_bytes(z_range(params, n_bits))?);
        out.extend_from_slice(&self.z2.to_bytes(z_range(params, n_bits))?);
        out.extend_from_slice(&uint_to_be(&self.lambda1, fp.d_len)?);
        out.extend_from_slice(&uint_to_be(&self.lambda2, fp.d_len)?);
        out.extend_from_slice(&uint_to_be(&self.w, fp.d_len)?);
        Ok(out)
    }

    pub fn decode(bytes: &[u8], params: &Params, fp: &FacParams, n_bits: u32) -> Result<Self> {
        if bytes.len() != Self::encoded_len(params, fp, n_bits) {
            return Err(Error::InvalidEncoding);
        }
        let dl = fp.d_len;
        let (el, zl) = (sbig_len(e_range(params)), sbig_len(z_range(params, n_bits)));
        let mut pos = 0;
        let mut take = |len: usize| {
            let s = &bytes[pos..pos + len];
            pos += len;
            s
        };
        let uint = |s: &[u8], bound: &BoxedUint| -> Result<BoxedUint> {
            let v = uint_from_be(s, bound.bits())?;
            if resized(&v, bound.bits_precision()).cmp_vartime(resized(bound, v.bits_precision()))
                != core::cmp::Ordering::Less
            {
                return Err(Error::OutOfRange);
            }
            Ok(v)
        };
        let p_tilde = uint(take(dl), &fp.d_val)?;
        let q_tilde = uint(take(dl), &fp.d_val)?;
        let e = SBig::from_bytes(take(el), e_range(params))?;
        let z1 = SBig::from_bytes(take(zl), z_range(params, n_bits))?;
        let z2 = SBig::from_bytes(take(zl), z_range(params, n_bits))?;
        let lambda1 = uint(take(dl), fp.half.as_ref())?;
        let lambda2 = uint(take(dl), fp.half.as_ref())?;
        let w = uint(take(dl), fp.half.as_ref())?;
        Ok(Self {
            p_tilde,
            q_tilde,
            e,
            z1,
            z2,
            lambda1,
            lambda2,
            w,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{
        params::PARAMS_128,
        rsa::tough::{ToughSpec, sample_rsa_with, sample_tough_prime},
    };
    use crypto_primes::{Flavor, is_prime};
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::{sync::OnceLock, time::Instant};

    const SPEC: ToughSpec = ToughSpec { count: 4, bits: 64 };
    const NB: u32 = 512;

    fn params() -> Params {
        Params {
            ell: 16,
            nu: 16,
            ..PARAMS_128
        }
    }

    struct Fx {
        n: BoxedUint,
        p: BoxedUint,
        q: BoxedUint,
        fp: FacParams,
    }

    fn fx() -> &'static Fx {
        static F: OnceLock<Fx> = OnceLock::new();
        F.get_or_init(|| {
            let mut rng = ChaCha8Rng::seed_from_u64(21);
            let m = sample_rsa_with(&mut rng, NB, SPEC).unwrap();
            let pr = params();
            let d_bits = NB + 2 * pr.ell + 2 * pr.nu + 4;
            let d = sample_tough_prime(&mut rng, d_bits, 7, ToughSpec::SAFE).unwrap();
            Fx {
                n: m.n.clone(),
                p: m.secret.p1.p().clone(),
                q: m.secret.p2.p().clone(),
                fp: FacParams::new(d.p().clone()).unwrap(),
            }
        })
    }

    fn tx() -> Transcript {
        Transcript::new("test/fac")
    }

    fn honest() -> FacProof {
        let f = fx();
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        FacProof::prove(
            &mut rng,
            &tx(),
            &params(),
            &f.fp,
            &f.n,
            &FacWitness { p: &f.p, q: &f.q },
        )
        .unwrap()
    }

    fn ok(p: &FacProof) -> bool {
        let f = fx();
        p.verify(&tx(), &params(), &f.fp, &f.n).is_ok()
    }

    #[test]
    fn standard_d_is_strong_prime() {
        let fp = FacParams::standard().unwrap();
        assert_eq!(fp.d().bits(), 3460);
        assert!(is_prime(Flavor::Any, fp.d()));
        assert!(is_prime(Flavor::Any, &fp.half.as_ref().clone()));
        // d > 2^{n+2ℓ+2ν+3} for n = 3072
        assert!(fp.check_size(&PARAMS_128, 3072).is_ok());
    }

    #[test]
    fn honest_passes() {
        let p = honest();
        assert!(ok(&p));
        // several seeds
        let f = fx();
        for seed in 0..5 {
            let mut rng = ChaCha8Rng::seed_from_u64(100 + seed);
            let pr = FacProof::prove(
                &mut rng,
                &tx(),
                &params(),
                &f.fp,
                &f.n,
                &FacWitness { p: &f.p, q: &f.q },
            )
            .unwrap();
            assert!(ok(&pr));
        }
    }

    #[test]
    fn wrong_context_fails() {
        let f = fx();
        let p = honest();
        assert!(
            p.verify(&Transcript::new("other"), &params(), &f.fp, &f.n)
                .is_err()
        );
        let n2 = f.n.wrapping_add(BoxedUint::from(2u64));
        assert!(p.verify(&tx(), &params(), &f.fp, &n2).is_err());
    }

    #[test]
    fn modified_fields_fail() {
        let one = BoxedUint::one_with_precision(64);
        let inc = |x: &BoxedUint| {
            resized(x, x.bits_precision() + 64).wrapping_add(resized(&one, x.bits_precision() + 64))
        };
        let f = fx();
        let mut p = honest();
        p.p_tilde = inc(&p.p_tilde);
        assert!(!ok(&p));
        let mut p = honest();
        p.q_tilde = inc(&p.q_tilde);
        assert!(!ok(&p));
        let mut p = honest();
        p.e = p.e.add(&SBig::from_i64(1));
        assert!(!ok(&p));
        let mut p = honest();
        p.z1 = p.z1.add(&SBig::from_i64(1));
        assert!(!ok(&p));
        let mut p = honest();
        p.z2 = p.z2.add(&SBig::from_i64(1));
        assert!(!ok(&p));
        let mut p = honest();
        p.lambda1 = inc(&p.lambda1);
        assert!(!ok(&p));
        let mut p = honest();
        p.lambda2 = inc(&p.lambda2);
        assert!(!ok(&p));
        let mut p = honest();
        p.w = inc(&p.w);
        assert!(!ok(&p));
        // λ ≥ (d−1)/2 even though ≡ same mod (d−1)/2
        let mut p = honest();
        p.lambda1 = resized(&p.lambda1, 1024).wrapping_add(resized(f.fp.half.as_ref(), 1024));
        assert!(!ok(&p));
        // P̃ = 0, P̃ = d
        let mut p = honest();
        p.p_tilde = BoxedUint::zero_with_precision(64);
        assert!(!ok(&p));
        let mut p = honest();
        p.p_tilde = f.fp.d().clone();
        assert!(!ok(&p));
    }

    #[test]
    fn z_range_boundaries() {
        let f = fx();
        let pr = params();
        let zr = z_range(&pr, f.n.bits());
        let top = SBig::from_uint(BoxedUint::one_with_precision(zr.bits() + 64).shl(zr.bits() - 1));
        // |z| ≤ 2^{R-1} is in range, +1 is out; the proof then fails the range check first.
        assert!(top.in_range(zr));
        assert!(!top.add(&SBig::from_i64(1)).in_range(zr));
        assert!(top.negate().add(&SBig::from_i64(1)).in_range(zr));
        assert!(!top.negate().in_range(zr));
        let mut p = honest();
        p.z1 = top.add(&SBig::from_i64(1));
        assert!(!ok(&p));
        let mut p = honest();
        p.z2 = top.negate();
        assert!(!ok(&p));
    }

    #[test]
    fn wrong_witness_and_unbalanced() {
        let f = fx();
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        fn sw<'a>(p: &'a BoxedUint, q: &'a BoxedUint) -> FacWitness<'a> {
            FacWitness { p, q }
        }
        // product mismatch
        let other = sample_tough_prime(&mut rng, 256, 3, ToughSpec::SAFE).unwrap();
        assert!(
            FacProof::prove(
                &mut rng,
                &tx(),
                &params(),
                &f.fp,
                &f.n,
                &sw(&f.p, other.p())
            )
            .is_err()
        );
        let forged = FacProof::prove_inner(
            &mut rng,
            &tx(),
            &params(),
            &f.fp,
            &f.n,
            &sw(&f.p, other.p()),
            false,
        )
        .unwrap();
        assert!(!ok(&forged));
        // unbalanced N = small·large (64-bit prime, 448-bit cofactor): honest prover cannot stay in range
        let small = crypto_primes::random_prime::<BoxedUint, _>(&mut rng, Flavor::Any, 64);
        let large = crypto_primes::random_prime::<BoxedUint, _>(&mut rng, Flavor::Any, 448);
        let n = small.concatenating_mul(&large);
        let nb = n.bits();
        let pr = Params {
            ell: 16,
            nu: 8,
            ..params()
        };
        // d from the fixture is large enough for ν = 8 too
        assert!(f.fp.check_size(&pr, nb).is_ok());
        assert!(FacProof::prove(&mut rng, &tx(), &pr, &f.fp, &n, &sw(&small, &large)).is_err());
        let forged =
            FacProof::prove_inner(&mut rng, &tx(), &pr, &f.fp, &n, &sw(&small, &large), false)
                .unwrap();
        assert!(forged.verify(&tx(), &pr, &f.fp, &n).is_err());
        // reversed order (q small) is symmetric
        let forged =
            FacProof::prove_inner(&mut rng, &tx(), &pr, &f.fp, &n, &sw(&large, &small), false)
                .unwrap();
        assert!(forged.verify(&tx(), &pr, &f.fp, &n).is_err());
    }

    #[test]
    fn encode_decode() {
        let f = fx();
        let pr = params();
        let p = honest();
        let bytes = p.encode(&pr, &f.fp, NB).unwrap();
        assert_eq!(bytes.len(), FacProof::encoded_len(&pr, &f.fp, NB));
        let back = FacProof::decode(&bytes, &pr, &f.fp, NB).unwrap();
        assert!(ok(&back));
        assert!(FacProof::decode(&bytes[1..], &pr, &f.fp, NB).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(FacProof::decode(&long, &pr, &f.fp, NB).is_err());
        // λ1 out of range: all 0xff
        let dl = f.fp.d_len;
        let mut bad = bytes.clone();
        let off = bytes.len() - 3 * dl;
        bad[off..off + dl].fill(0xff);
        assert!(FacProof::decode(&bad, &pr, &f.fp, NB).is_err());
        // negative zero in z1
        let (el, zl) = (sbig_len(e_range(&pr)), sbig_len(z_range(&pr, NB)));
        let mut bad = bytes.clone();
        let o = 2 * dl + el;
        bad[o] = 1;
        bad[o + 1..o + zl].fill(0);
        assert!(FacProof::decode(&bad, &pr, &f.fp, NB).is_err());
    }

    #[test]
    #[ignore]
    fn full_size_timings() {
        let mut rng = ChaCha8Rng::seed_from_u64(78);
        let spec = ToughSpec::from_params(&PARAMS_128);
        let m = sample_rsa_with(&mut rng, PARAMS_128.n_rsa, spec).unwrap();
        let (p, q) = (m.secret.p1.p().clone(), m.secret.p2.p().clone());
        let fp = FacParams::standard().unwrap();
        let t0 = Instant::now();
        let pr = FacProof::prove(
            &mut rng,
            &tx(),
            &PARAMS_128,
            &fp,
            &m.n,
            &FacWitness { p: &p, q: &q },
        )
        .unwrap();
        std::println!("fac prove: {:?}", t0.elapsed());
        let t0 = Instant::now();
        pr.verify(&tx(), &PARAMS_128, &fp, &m.n).unwrap();
        std::println!("fac verify: {:?}", t0.elapsed());
        let bytes = pr.encode(&PARAMS_128, &fp, 3072).unwrap();
        std::println!("fac proof size: {} bytes", bytes.len());
        let back = FacProof::decode(&bytes, &PARAMS_128, &fp, 3072).unwrap();
        back.verify(&tx(), &PARAMS_128, &fp, &m.n).unwrap();
        let mut bad = pr.clone();
        bad.w = bad
            .w
            .wrapping_add(BoxedUint::one_with_precision(bad.w.bits_precision()));
        assert!(bad.verify(&tx(), &PARAMS_128, &fp, &m.n).is_err());
    }
}
