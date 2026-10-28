//! Π_mod (paper Protocol 5): `N` is a product of two primes `p1 ≡ 3`, `p2 ≡ 7 (mod 8)` with
//! `gcd(N, φ(N)) = 1`.
//!
//! The challenges `y_i ∈ Z*_N` are derived from the transcript (the only input is `N`), so the
//! proof is just `r_mod` tuples `(a, b, x, z)`:
//! `x⁴ = (−1)^a · w^b · y (mod N)` with `w = 2^N mod N`, and `z^N = y (mod N)`.
use alloc::vec::Vec;
use crypto_bigint::{BoxedUint, ConcatenatingMul, Gcd, NonZero, ctutils::CtSelect};
use crypto_primes::{Flavor, is_prime};
use rand_core::CryptoRng;

use crate::{
    arith::{
        monty::{Modulus, Residue},
        sbig::{SBig, resized},
    },
    error::{Error, Result},
    params::Params,
    transcript::{Transcript, uint_from_be, uint_to_be},
};

/// Secret input: the two primes (`p1 ≡ 3`, `p2 ≡ 7 mod 8`).
pub struct ModWitness<'a> {
    pub p1: &'a BoxedUint,
    pub p2: &'a BoxedUint,
}

/// One repetition `(a, b, x, z)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModRep {
    pub a: bool,
    pub b: bool,
    pub x: BoxedUint,
    pub z: BoxedUint,
}

/// Proof: `r_mod` repetitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModProof {
    pub reps: Vec<ModRep>,
}

fn n_bytes(n_bits: u32) -> usize {
    (n_bits as usize).div_ceil(8)
}

/// Challenges `y_1..y_r` and `w = 2^N mod N` are public functions of `N`.
fn challenges(
    tx: &Transcript,
    params: &Params,
    mn: &Modulus,
    n: &BoxedUint,
) -> Result<Vec<Residue>> {
    let mut t = tx.clone();
    t.append("zk", b"mod");
    t.append_uint("N", n, n_bytes(n.bits()))?;
    let mut ch = t.challenge("y");
    let mut ys = Vec::with_capacity(params.r_mod as usize);
    for _ in 0..params.r_mod {
        ys.push(ch.unit_mod(mn)?);
    }
    Ok(ys)
}

fn small_w(mn: &Modulus, n: &BoxedUint) -> Result<Residue> {
    let two = mn.residue(&BoxedUint::from(2u64));
    mn.pow_vartime(&two, &SBig::from_uint(n.clone()))
}

/// `(−1)^a · w^b · y`.
fn target(y: &Residue, w: &Residue, a: bool, b: bool) -> Residue {
    let mut v = y.clone();
    if a {
        v = v.neg();
    }
    if b {
        v = v.mul(w);
    }
    v
}

/// Per-prime secret data for the prover.
struct PrimeCtx {
    ring: Modulus,
    bits: u32,
    /// `(p−1)/2`.
    half: SBig,
    /// `((p+1)/4)² mod (p−1)/2`: maps a QR to its QR fourth root.
    root_exp: SBig,
    /// `N^{-1} mod (p−1)`.
    n_inv: SBig,
}

fn rem(x: &BoxedUint, m: &BoxedUint) -> Result<BoxedUint> {
    let nz = Option::<NonZero<BoxedUint>>::from(m.to_nz()).ok_or(Error::InvalidModulus)?;
    Ok(SBig::from_uint(x.clone()).rem_euclid(&nz))
}

impl PrimeCtx {
    fn new(p: &BoxedUint, n: &BoxedUint) -> Result<Self> {
        let prec = p.bits_precision();
        let one = BoxedUint::one_with_precision(prec);
        let pm1 = p.wrapping_sub(&one);
        let half = pm1.shr_vartime(1).ok_or(Error::InvalidModulus)?;
        let wide = resized(p, prec + 64);
        let t = wide
            .wrapping_add(BoxedUint::one_with_precision(prec + 64))
            .shr_vartime(2)
            .ok_or(Error::InvalidModulus)?;
        let t2 = t.concatenating_mul(&t);
        let root_exp = rem(&t2, &half)?;
        // N^{-1} mod (p−1) (even modulus; fails iff gcd(N, p−1) ≠ 1)
        let pm1_nz =
            Option::<NonZero<BoxedUint>>::from(pm1.to_nz()).ok_or(Error::InvalidModulus)?;
        let n_red = rem(n, &pm1)?;
        let n_inv =
            Option::<BoxedUint>::from(n_red.invert_mod(&pm1_nz)).ok_or(Error::NotInvertible)?;
        Ok(Self {
            ring: Modulus::new(p.clone())?,
            bits: p.bits(),
            half: SBig::from_uint(half),
            root_exp: SBig::from_uint(root_exp),
            n_inv: SBig::from_uint(n_inv),
        })
    }

    fn residue(&self, y: &Residue) -> Residue {
        self.ring.residue(&y.retrieve())
    }
}

/// CRT combination of `r1 mod p1`, `r2 mod p2` into `Z_N`.
fn crt(c1: &PrimeCtx, r1: &Residue, p2: &BoxedUint, r2: &Residue, mn: &Modulus) -> Result<Residue> {
    let x2 = r2.retrieve();
    let x2_in_1 = c1.ring.residue(&x2);
    let inv = c1.ring.invert(&c1.ring.residue(p2))?;
    let t = r1.sub(&x2_in_1).mul(&inv).retrieve();
    let x = p2
        .concatenating_mul(&t)
        .wrapping_add(resized(&x2, p2.bits_precision() + t.bits_precision()));
    Ok(mn.residue(&x))
}

fn random_neg<R: CryptoRng + ?Sized>(rng: &mut R, r: &Residue) -> Residue {
    let n = r.neg();
    let flip = crypto_bigint::Choice::from_u8_lsb((rng.next_u32() & 1) as u8);
    Residue::from_montgomery(
        r.as_montgomery().ct_select(n.as_montgomery(), flip),
        r.params(),
    )
}

impl ModProof {
    /// Proves that `N = p1·p2` is well formed.
    pub fn prove<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        n: &BoxedUint,
        w: &ModWitness<'_>,
    ) -> Result<Self> {
        Self::prove_inner(rng, tx, params, n, w, true)
    }

    fn prove_inner<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        n: &BoxedUint,
        wit: &ModWitness<'_>,
        check: bool,
    ) -> Result<Self> {
        if check {
            let prod = wit.p1.concatenating_mul(wit.p2);
            if resized(&prod, n.bits_precision()) != resized(n, prod.bits_precision()) {
                return Err(Error::InvalidModulus);
            }
            if wit.p1.as_words()[0] & 7 != 3 || wit.p2.as_words()[0] & 7 != 7 {
                return Err(Error::InvalidModulus);
            }
        }
        let mn = Modulus::new(n.clone())?;
        let c1 = PrimeCtx::new(wit.p1, n)?;
        let c2 = PrimeCtx::new(wit.p2, n)?;
        let ys = challenges(tx, params, &mn, n)?;
        let w = small_w(&mn, n)?;
        let one = BoxedUint::one_with_precision(64);
        let is_plus = |r: &Residue| resized(&r.retrieve(), 64) == one;

        let mut reps = Vec::with_capacity(ys.len());
        for y in &ys {
            let y1 = c1.residue(y);
            let y2 = c2.residue(y);
            // Legendre symbols of y: a, b are public so the branch is harmless.
            let l1 = c1.ring.pow_ct(&y1, &c1.half, c1.bits)?;
            let l2 = c2.ring.pow_ct(&y2, &c2.half, c2.bits)?;
            // −1 has symbols (−1,−1), w = 2^N has symbols (−1,+1) for (p1,p2) ≡ (3,7) mod 8.
            let a = !is_plus(&l2);
            let b = !is_plus(&l1) ^ a;
            let y0 = target(y, &w, a, b);
            let y01 = c1.residue(&y0);
            let y02 = c2.residue(&y0);
            let r1 = random_neg(rng, &c1.ring.pow_ct(&y01, &c1.root_exp, c1.bits)?);
            let r2 = random_neg(rng, &c2.ring.pow_ct(&y02, &c2.root_exp, c2.bits)?);
            let x = crt(&c1, &r1, wit.p2, &r2, &mn)?;
            let z1 = c1.ring.pow_ct(&y1, &c1.n_inv, c1.bits)?;
            let z2 = c2.ring.pow_ct(&y2, &c2.n_inv, c2.bits)?;
            let z = crt(&c1, &z1, wit.p2, &z2, &mn)?;
            reps.push(ModRep {
                a,
                b,
                x: x.retrieve(),
                z: z.retrieve(),
            });
        }
        Ok(Self { reps })
    }

    /// Verifies the proof for `N`; `min_bits` is the required bit length of `N`.
    pub fn verify(
        &self,
        tx: &Transcript,
        params: &Params,
        n: &BoxedUint,
        min_bits: u32,
    ) -> Result<()> {
        let fail = Error::VerificationFailed;
        if n.bits() < min_bits || self.reps.len() != params.r_mod as usize {
            return Err(fail);
        }
        if n.as_words()[0] & 3 != 1 {
            return Err(fail);
        }
        let mn = Modulus::new(n.clone()).map_err(|_| fail)?;
        if mn.jacobi_vartime(&BoxedUint::from(2u64)) != -1 {
            return Err(fail);
        }
        // Cheap per-repetition range checks before any exponentiation.
        for rep in &self.reps {
            for v in [&rep.x, &rep.z] {
                let v = resized(v, n.bits_precision());
                let nn = resized(n, v.bits_precision());
                if v.cmp_vartime(&nn) != core::cmp::Ordering::Less {
                    return Err(fail);
                }
                if !bool::from(v.gcd(&nn).is_one()) {
                    return Err(fail);
                }
            }
        }
        if is_prime(Flavor::Any, n) {
            return Err(fail);
        }
        let ys = challenges(tx, params, &mn, n)?;
        let w = small_w(&mn, n)?;
        for (rep, y) in self.reps.iter().zip(&ys) {
            let x = mn.residue(&rep.x);
            let x4 = x.square().square();
            if x4 != target(y, &w, rep.a, rep.b) {
                return Err(fail);
            }
        }
        let n_exp = SBig::from_uint(n.clone());
        for (rep, y) in self.reps.iter().zip(&ys) {
            let z = mn.residue(&rep.z);
            if mn.pow_vartime(&z, &n_exp)? != *y {
                return Err(fail);
            }
        }
        Ok(())
    }

    /// Encoded length: `r_mod · (1 + 2·⌈bits(N)/8⌉)`.
    pub fn encoded_len(params: &Params, n_bits: u32) -> usize {
        params.r_mod as usize * (1 + 2 * n_bytes(n_bits))
    }

    /// Per repetition: byte `a | b << 1`, then `x` and `z` as fixed-width big-endian.
    pub fn encode(&self, n_bits: u32) -> Result<Vec<u8>> {
        let len = n_bytes(n_bits);
        let mut out = Vec::with_capacity(self.reps.len() * (1 + 2 * len));
        for r in &self.reps {
            out.push(u8::from(r.a) | (u8::from(r.b) << 1));
            out.extend_from_slice(&uint_to_be(&r.x, len)?);
            out.extend_from_slice(&uint_to_be(&r.z, len)?);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8], params: &Params, n_bits: u32) -> Result<Self> {
        if bytes.len() != Self::encoded_len(params, n_bits) {
            return Err(Error::InvalidEncoding);
        }
        let len = n_bytes(n_bits);
        let mut reps = Vec::with_capacity(params.r_mod as usize);
        for chunk in bytes.chunks_exact(1 + 2 * len) {
            if chunk[0] > 3 {
                return Err(Error::InvalidEncoding);
            }
            reps.push(ModRep {
                a: chunk[0] & 1 == 1,
                b: chunk[0] & 2 == 2,
                x: uint_from_be(&chunk[1..1 + len], n_bits)?,
                z: uint_from_be(&chunk[1 + len..], n_bits)?,
            });
        }
        Ok(Self { reps })
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
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::{sync::OnceLock, time::Instant};

    const SPEC: ToughSpec = ToughSpec { count: 4, bits: 64 };

    fn params() -> Params {
        Params {
            r_mod: 8,
            ..PARAMS_128
        }
    }

    struct Fx {
        n: BoxedUint,
        p1: BoxedUint,
        p2: BoxedUint,
    }

    fn fx() -> &'static Fx {
        static F: OnceLock<Fx> = OnceLock::new();
        F.get_or_init(|| {
            let mut rng = ChaCha8Rng::seed_from_u64(11);
            let m = sample_rsa_with(&mut rng, 512, SPEC).unwrap();
            Fx {
                n: m.n.clone(),
                p1: m.secret.p1.p().clone(),
                p2: m.secret.p2.p().clone(),
            }
        })
    }

    fn tx() -> Transcript {
        Transcript::new("test/mod")
    }

    fn honest() -> ModProof {
        let f = fx();
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        ModProof::prove(
            &mut rng,
            &tx(),
            &params(),
            &f.n,
            &ModWitness {
                p1: &f.p1,
                p2: &f.p2,
            },
        )
        .unwrap()
    }

    #[test]
    fn honest_passes() {
        let f = fx();
        honest().verify(&tx(), &params(), &f.n, 512).unwrap();
        // a,b take all four values over enough repetitions
        let p = Params {
            r_mod: 64,
            ..PARAMS_128
        };
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        let pr = ModProof::prove(
            &mut rng,
            &tx(),
            &p,
            &f.n,
            &ModWitness {
                p1: &f.p1,
                p2: &f.p2,
            },
        )
        .unwrap();
        pr.verify(&tx(), &p, &f.n, 512).unwrap();
        for ab in 0..4u8 {
            assert!(
                pr.reps
                    .iter()
                    .any(|r| u8::from(r.a) | (u8::from(r.b) << 1) == ab)
            );
        }
    }

    #[test]
    fn wrong_transcript_or_min_bits() {
        let f = fx();
        let pr = honest();
        assert!(
            pr.verify(&Transcript::new("other"), &params(), &f.n, 512)
                .is_err()
        );
        assert!(pr.verify(&tx(), &params(), &f.n, 513).is_err());
    }

    #[test]
    fn modified_fields_fail() {
        let f = fx();
        let one = BoxedUint::one_with_precision(64);
        for i in [0usize, 3, 7] {
            let mut p = honest();
            p.reps[i].a = !p.reps[i].a;
            assert!(p.verify(&tx(), &params(), &f.n, 512).is_err());
            let mut p = honest();
            p.reps[i].b = !p.reps[i].b;
            assert!(p.verify(&tx(), &params(), &f.n, 512).is_err());
            let mut p = honest();
            p.reps[i].x = resized(&p.reps[i].x, 576).wrapping_add(resized(&one, 576));
            assert!(p.verify(&tx(), &params(), &f.n, 512).is_err());
            let mut p = honest();
            p.reps[i].z = resized(&p.reps[i].z, 576).wrapping_add(resized(&one, 576));
            assert!(p.verify(&tx(), &params(), &f.n, 512).is_err());
            // −x is another valid 4th root
            let mut p = honest();
            p.reps[i].x = resized(&f.n, 576).wrapping_sub(resized(&p.reps[i].x, 576));
            p.verify(&tx(), &params(), &f.n, 512).unwrap();
            // x = N (out of range)
            let mut p = honest();
            p.reps[i].x = f.n.clone();
            assert!(p.verify(&tx(), &params(), &f.n, 512).is_err());
            let mut p = honest();
            p.reps[i].z = BoxedUint::zero_with_precision(64);
            assert!(p.verify(&tx(), &params(), &f.n, 512).is_err());
        }
        let mut p = honest();
        p.reps.pop();
        assert!(p.verify(&tx(), &params(), &f.n, 512).is_err());
    }

    #[test]
    fn bad_moduli_fail() {
        let f = fx();
        let pr = honest();
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        // N + 2 ≡ 3 mod 4
        let n3 = f.n.wrapping_add(BoxedUint::from(2u64));
        assert!(pr.verify(&tx(), &params(), &n3, 512).is_err());
        // prime N
        let pm = sample_tough_prime(&mut rng, 512, 3, ToughSpec::SAFE).unwrap();
        let pn = pm.p().clone();
        assert!(pr.verify(&tx(), &params(), &pn, 512).is_err());
        // even N
        let ne = f.n.wrapping_sub(BoxedUint::one());
        assert!(pr.verify(&tx(), &params(), &ne, 512).is_err());
        // prime N ≡ 5 mod 8 passes every check except compositeness
        let p5 = loop {
            let c = crypto_primes::random_prime::<BoxedUint, _>(&mut rng, Flavor::Any, 256);
            if c.as_words()[0] & 7 == 5 {
                break c;
            }
        };
        assert!(pr.verify(&tx(), &params(), &p5, 256).is_err());
        // N = p·q with both ≡ 3 mod 8: prover refuses; forged (unchecked) proof fails
        let a = sample_tough_prime(&mut rng, 256, 3, ToughSpec::SAFE).unwrap();
        let b = sample_tough_prime(&mut rng, 256, 3, ToughSpec::SAFE).unwrap();
        let n33 = a.p().concatenating_mul(b.p());
        let w = ModWitness {
            p1: a.p(),
            p2: b.p(),
        };
        assert!(ModProof::prove(&mut rng, &tx(), &params(), &n33, &w).is_err());
        let forged = ModProof::prove_inner(&mut rng, &tx(), &params(), &n33, &w, false).unwrap();
        assert!(forged.verify(&tx(), &params(), &n33, 512).is_err());
        // wrong order (7, 3)
        let w2 = ModWitness {
            p1: &f.p2,
            p2: &f.p1,
        };
        assert!(ModProof::prove(&mut rng, &tx(), &params(), &f.n, &w2).is_err());
        // wrong witness product
        let w3 = ModWitness {
            p1: &f.p1,
            p2: a.p(),
        };
        assert!(ModProof::prove(&mut rng, &tx(), &params(), &f.n, &w3).is_err());
    }

    #[test]
    fn three_factor_modulus_fails() {
        let mut rng = ChaCha8Rng::seed_from_u64(10);
        let p1 = sample_tough_prime(&mut rng, 200, 3, ToughSpec::SAFE).unwrap();
        let p2 = sample_tough_prime(&mut rng, 200, 7, ToughSpec::SAFE).unwrap();
        // r ≡ 1 mod 8, so N ≡ 1 mod 4 and Jacobi(2/N) = −1 hold
        let r = loop {
            let c = crypto_primes::random_prime::<BoxedUint, _>(&mut rng, Flavor::Any, 112);
            if c.as_words()[0] & 7 == 1 {
                break c;
            }
        };
        let n = p1.p().concatenating_mul(p2.p()).concatenating_mul(&r);
        let w = ModWitness {
            p1: p1.p(),
            p2: &p2.p().concatenating_mul(&r),
        };
        let forged = ModProof::prove_inner(&mut rng, &tx(), &params(), &n, &w, false);
        if let Ok(f) = forged {
            assert!(f.verify(&tx(), &params(), &n, 400).is_err());
        }
        // random junk proof
        let junk = ModProof {
            reps: (0..8)
                .map(|i| ModRep {
                    a: false,
                    b: false,
                    x: BoxedUint::from(5u64 + i),
                    z: BoxedUint::from(7u64 + i),
                })
                .collect(),
        };
        assert!(junk.verify(&tx(), &params(), &n, 400).is_err());
    }

    #[test]
    fn encode_decode() {
        let f = fx();
        let pr = honest();
        let bytes = pr.encode(f.n.bits()).unwrap();
        assert_eq!(bytes.len(), ModProof::encoded_len(&params(), 512));
        let back = ModProof::decode(&bytes, &params(), 512).unwrap();
        back.verify(&tx(), &params(), &f.n, 512).unwrap();
        assert!(ModProof::decode(&bytes[1..], &params(), 512).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(ModProof::decode(&long, &params(), 512).is_err());
        let mut bad = bytes.clone();
        bad[0] = 4;
        assert!(ModProof::decode(&bad, &params(), 512).is_err());
    }

    #[test]
    #[ignore]
    fn full_size_timings() {
        let mut rng = ChaCha8Rng::seed_from_u64(77);
        let spec = ToughSpec::from_params(&PARAMS_128);
        let t0 = Instant::now();
        let m = sample_rsa_with(&mut rng, PARAMS_128.n_rsa, spec).unwrap();
        std::println!("sample_rsa: {:?}", t0.elapsed());
        let (p1, p2) = (m.secret.p1.p().clone(), m.secret.p2.p().clone());
        let t0 = Instant::now();
        let pr = ModProof::prove(
            &mut rng,
            &tx(),
            &PARAMS_128,
            &m.n,
            &ModWitness { p1: &p1, p2: &p2 },
        )
        .unwrap();
        std::println!("mod prove: {:?}", t0.elapsed());
        let t0 = Instant::now();
        pr.verify(&tx(), &PARAMS_128, &m.n, PARAMS_128.n_rsa)
            .unwrap();
        std::println!("mod verify: {:?}", t0.elapsed());
        let bytes = pr.encode(PARAMS_128.n_rsa).unwrap();
        std::println!("mod proof size: {} bytes", bytes.len());
        let mut bad = pr.clone();
        bad.reps[63].a = !bad.reps[63].a;
        assert!(
            bad.verify(&tx(), &PARAMS_128, &m.n, PARAMS_128.n_rsa)
                .is_err()
        );
    }
}
