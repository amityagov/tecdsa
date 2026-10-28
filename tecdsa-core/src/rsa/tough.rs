//! Algorithm 3: SampleRSA / SampleDF.
//!
//! A *tough prime* is a prime `p = 2·q_1⋯q_k + 1` where `q_1..q_k` are distinct primes of
//! about `tough_bits` bits each (`k = tough_count`; the last factor is drawn from the
//! interval that makes `p` exactly the requested length, so it may deviate slightly in size).
//! With `k = 1` this is a safe prime.
//!
//! * `SampleRSA`: `N = p1·p2`, `p1 ≡ 3`, `p2 ≡ 7 (mod 8)`, `gcd(p1−1, p2−1) = 2`
//!   (the prime sets of `(p1−1)/2` and `(p2−1)/2` are disjoint).
//! * `SampleDF`: `N̂` as above, `t` a random square in `Z*_N̂`, `s_i = t^{λ_i}`,
//!   `λ_i ← [2^{2ℓ}]`. The factorization and `λ_i` are returned in [`DfSecret`] so that the
//!   caller can drop (and thereby zeroize) them after the proof (FR-S4).
//!
//! All sizes are in bits. Sampling is variable-time: it only handles values that are
//! rejected or published (candidates), and the final primes stay inside zeroizing structs.

use alloc::vec::Vec;
use core::fmt;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{
    BoxedUint, ConcatenatingMul, Gcd, Limb, NonZero, RandomBits, RandomMod, Resize,
};
use crypto_primes::{Flavor, is_prime, random_prime};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::Params;

/// Smallest accepted size of a prime factor.
const MIN_PRIME_BITS: u32 = 32;
/// Number of small primes used for trial-division pre-sieving.
const SIEVE_LIMIT: u32 = 16384;
/// Retries for the first `k−1` factors before giving up.
const MAX_PREFIX_ATTEMPTS: u32 = 100_000;

/// Errors of the tough-prime samplers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToughError {
    /// The requested sizes are inconsistent (no room for `p'`, bad residue, too small).
    BadSize,
}

impl fmt::Display for ToughError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToughError::BadSize => f.write_str("inconsistent tough-prime sizes"),
        }
    }
}

/// Shape of tough primes: `p = 2·∏ q_i + 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToughSpec {
    /// Number of primes `q_i` in `(p−1)/2`.
    pub count: u32,
    /// Bit size of each `q_i` (`0`: unconstrained, only allowed with `count == 1`).
    pub bits: u32,
}

impl ToughSpec {
    /// Spec from a parameter profile.
    pub const fn from_params(params: &Params) -> Self {
        Self {
            count: params.tough_count,
            bits: params.tough_bits,
        }
    }
    /// Safe primes: `(p−1)/2` is a single prime.
    pub const SAFE: Self = Self { count: 1, bits: 0 };
}

/// A tough prime together with its factorization of `(p−1)/2`. Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct ToughPrime {
    p: BoxedUint,
    factors: Vec<BoxedUint>,
}

impl ToughPrime {
    /// The prime `p`.
    pub fn p(&self) -> &BoxedUint {
        &self.p
    }
    /// The primes `q_i` with `(p−1)/2 = ∏ q_i`.
    pub fn factors(&self) -> &[BoxedUint] {
        &self.factors
    }
    /// `(p−1)/2`.
    pub fn half(&self) -> BoxedUint {
        self.factors
            .iter()
            .fold(BoxedUint::one(), |a, q| a.concatenating_mul(q))
    }
}

impl fmt::Debug for ToughPrime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ToughPrime(***)")
    }
}

/// Secret part of an RSA modulus. Zeroized on drop; deliberately not `Clone`.
#[derive(ZeroizeOnDrop)]
pub struct RsaSecret {
    pub p1: ToughPrime,
    pub p2: ToughPrime,
}

impl fmt::Debug for RsaSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RsaSecret(***)")
    }
}

/// Output of `SampleRSA`.
pub struct RsaModulus {
    /// Public modulus `N = p1·p2`.
    pub n: BoxedUint,
    /// Factorization.
    pub secret: RsaSecret,
}

impl fmt::Debug for RsaModulus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsaModulus {{ n: {:?}, secret: *** }}", self.n.bits())
    }
}

/// Secret part of a DF tuple: factorization of `N̂` and the exponents. Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct DfSecret {
    pub rsa: RsaSecret,
    pub lambda1: BoxedUint,
    pub lambda2: BoxedUint,
}

impl fmt::Debug for DfSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DfSecret(***)")
    }
}

/// Output of `SampleDF`: public tuple `(N̂, t, s1, s2)` and the secret witness.
pub struct DfTuple {
    pub n_hat: BoxedUint,
    pub t: BoxedUint,
    pub s1: BoxedUint,
    pub s2: BoxedUint,
    pub secret: DfSecret,
}

impl fmt::Debug for DfTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DfTuple {{ n_hat: {:?} bits, secret: *** }}",
            self.n_hat.bits()
        )
    }
}

fn small_primes() -> Vec<NonZero<Limb>> {
    let mut sieve = alloc::vec![true; SIEVE_LIMIT as usize + 1];
    let mut out = Vec::new();
    for i in 2..=SIEVE_LIMIT {
        if sieve[i as usize] {
            if let Some(nz) = Option::from(NonZero::new(Limb::from_u32(i))) {
                out.push(nz);
            }
            let mut j = i * i;
            while j <= SIEVE_LIMIT {
                sieve[j as usize] = false;
                j += i;
            }
        }
    }
    out
}

const _: () = assert!(Limb::BITS == 64);

/// `x mod s` for a small `s < 2^20` using word-wise Horner (variable time, public/candidate data).
fn mod_small(x: &BoxedUint, s: u64) -> u64 {
    let a = (1u64 << 32) % s;
    let r_word = a * a % s; // 2^64 mod s
    x.as_words()
        .iter()
        .rev()
        .fold(0u64, |r, &w| (r * r_word % s + w % s) % s)
}

fn divisible_by_small(x: &BoxedUint, primes: &[NonZero<Limb>]) -> bool {
    primes.iter().any(|q| mod_small(x, q.get().0) == 0)
}

/// Temporary pool of secret primes.
#[derive(ZeroizeOnDrop)]
struct Pool(Vec<BoxedUint>);

/// Binomial coefficient C(n, k), saturating.
fn binom_sat(n: u32, k: u32) -> u128 {
    let mut r: u128 = 1;
    for i in 0..k {
        r = r.saturating_mul(u128::from(n - i)) / u128::from(i + 1);
    }
    r
}

/// Random prime in `[qlo, qhi]` with `q ≡ low2 (mod 4)`: pick a random start and search
/// the arithmetic progression `q0 + 4i` with an incremental small-prime sieve window.
fn random_prime_in<R: CryptoRng + ?Sized>(
    rng: &mut R,
    qlo: &BoxedUint,
    qhi: &BoxedUint,
    low2: u64,
    sieve: &[NonZero<Limb>],
) -> Option<BoxedUint> {
    const W: usize = 2048;
    let one = BoxedUint::one();
    let span = BoxedUint::from(4 * W as u64);
    let width = qhi.wrapping_sub(qlo).wrapping_sub(&span).wrapping_add(&one);
    let width_nz = Option::<NonZero<BoxedUint>>::from(width.to_nz())?;
    let mut marks = alloc::vec![false; W];
    loop {
        let mut q0 = BoxedUint::random_mod_vartime(rng, &width_nz).wrapping_add(qlo);
        let cur = q0.as_words()[0] & 3;
        q0 = q0
            .wrapping_sub(BoxedUint::from(cur))
            .wrapping_add(BoxedUint::from(low2));
        if q0 < *qlo {
            continue;
        }
        marks.iter_mut().for_each(|m| *m = false);
        for sp in sieve.iter().skip(1) {
            let s = sp.get().0;
            let r = mod_small(&q0, s);
            let inv2 = s.div_ceil(2);
            let inv4 = inv2 * inv2 % s;
            let mut i = ((s - r) % s) * inv4 % s;
            while (i as usize) < W {
                marks[i as usize] = true;
                i += s;
            }
        }
        for (i, m) in marks.iter().enumerate() {
            if *m {
                continue;
            }
            let q = q0.wrapping_add(BoxedUint::from(4 * i as u64));
            if q > *qhi {
                break;
            }
            if is_prime(Flavor::Any, &q) {
                return Some(q);
            }
        }
    }
}

/// Algorithm 1/3 of the paper: a pool `B` of ~`2ℓ`-bit primes, then random size-`k` subsets
/// `S` until `2·∏_{S} q + 1` is prime. Candidates are screened by residues mod small primes
/// computed from per-pool-prime residues (no big multiplication), and only survivors get a
/// product and a Miller–Rabin/Lucas test. Pool primes are drawn from a narrow band so that
/// the product lands in `[3·2^(bits−2), 2^bits)` with high probability.
fn sample_from_pool<R: CryptoRng + ?Sized>(
    rng: &mut R,
    bits: u32,
    t: u64,
    spec: ToughSpec,
    sieve: &[NonZero<Limb>],
) -> Result<ToughPrime, ToughError> {
    let k = spec.count;
    let b = spec.bits;
    let ku = k as usize;
    let prec = bits.div_ceil(64) * 64;
    let wide = prec + 64;
    let one = BoxedUint::one_with_precision(wide);
    let lo = BoxedUint::from(3u8).resize(wide).shl(bits - 2);
    let hi = one.shl(bits);
    // Target of ∏q: the middle of (lo/2, hi/2).
    let mid = lo.wrapping_add(&hi).shr(2);

    // Pool size: C(B,k) ≥ 6·bits subsets.
    let mut pool_n = k + 1;
    while binom_sat(pool_n, k) < 6 * u128::from(bits) {
        pool_n += 1;
    }
    let pn = pool_n as usize;

    // Largest j ∈ [0,255] with ((256+j)·2^(b−9))^k ≤ mid, fixing the band of the pool.
    let pow_k = |j: u32| -> BoxedUint {
        let q0 = BoxedUint::from(256 + j).resize(wide).shl(b - 9);
        let mut acc = one.clone();
        for _ in 0..k {
            acc = acc.concatenating_mul(&q0).resize(wide + 64 * k);
        }
        acc
    };
    let mid_big = mid.resize(wide + 64 * k);
    let (mut jl, mut jh) = (0u32, 255u32);
    while jl < jh {
        let m = (jl + jh).div_ceil(2);
        if pow_k(m) <= mid_big {
            jl = m;
        } else {
            jh = m - 1;
        }
    }
    let qlo = BoxedUint::from(256 + jl).resize(wide).shl(b - 9);
    let qhi = qlo.wrapping_add(qlo.shr(6));
    let q_max = one.shl(b).wrapping_sub(&one);
    let qhi = if qhi > q_max { q_max } else { qhi };

    let primes32: Vec<u32> = sieve.iter().map(|x| x.get().0 as u32).collect();
    let tries_per_pool = 16 * bits;
    let mut resid = alloc::vec![0u32; primes32.len() * pn];

    for _ in 0..MAX_PREFIX_ATTEMPTS.min(64) {
        // Pool: for p ≡ 3 (8) all q ≡ 1 (4); for p ≡ 7 (8) half of them are ≡ 3 (4).
        let mut pool = Pool(Vec::with_capacity(pn));
        while pool.0.len() < pn {
            let low2 = if t == 1 || pool.0.len() % 2 == 0 {
                1
            } else {
                3
            };
            let q = random_prime_in(rng, &qlo, &qhi, low2, sieve).ok_or(ToughError::BadSize)?;
            if !pool.0.contains(&q) {
                pool.0.push(q);
            }
        }
        let mod4: Vec<u64> = pool.0.iter().map(|q| q.as_words()[0] & 3).collect();
        for (i, sp) in sieve.iter().enumerate() {
            for (j, q) in pool.0.iter().enumerate() {
                resid[i * pn + j] = mod_small(q, sp.get().0) as u32;
            }
        }
        let mut idx: Vec<usize> = (0..pn).collect();
        let mut seen: Vec<u64> = Vec::new();
        for _ in 0..tries_per_pool {
            // Random k-subset (partial Fisher–Yates).
            for i in 0..ku {
                let r = rng.next_u32() as usize % (pn - i);
                idx.swap(i, i + r);
            }
            let sub = &idx[..ku];
            let prod4 = sub.iter().fold(1u64, |a, &j| (a * mod4[j]) & 3);
            if prod4 != t {
                continue;
            }
            let mut ok = true;
            for (i, &sp) in primes32.iter().enumerate() {
                let sp = u64::from(sp);
                let mut r = 2u64;
                for &j in sub {
                    r = r * u64::from(resid[i * pn + j]) % sp;
                }
                if r + 1 == sp {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }
            // Subset id (bitmask) to avoid retesting; pool sizes are < 64.
            let mask = sub.iter().fold(0u64, |a, &j| a | (1u64 << (j % 64)));
            if pn <= 64 {
                if seen.contains(&mask) {
                    continue;
                }
                seen.push(mask);
            }
            let m = sub.iter().fold(one.clone(), |a, &j| {
                a.concatenating_mul(&pool.0[j]).resize(wide)
            });
            let p = m.shl(1).wrapping_add(&one);
            if p < lo || p >= hi {
                continue;
            }
            let p = p.resize(prec);
            if !is_prime(Flavor::Any, &p) {
                continue;
            }
            let factors = sub
                .iter()
                .map(|&j| pool.0[j].clone().resize(prec))
                .collect();
            return Ok(ToughPrime { p, factors });
        }
    }
    Err(ToughError::BadSize)
}

/// Samples a tough prime `p = 2·∏q_i + 1` with `p ∈ [3·2^(bits−2), 2^bits)` (exactly
/// `bits` bits, top two bits set so that products of two such primes have full length)
/// and `p ≡ residue_mod8 (mod 8)`.
fn sample_tough_prime_inner<R: CryptoRng + ?Sized>(
    rng: &mut R,
    bits: u32,
    residue_mod8: u8,
    spec: ToughSpec,
    sieve: &[NonZero<Limb>],
) -> Result<ToughPrime, ToughError> {
    if residue_mod8 != 3 && residue_mod8 != 7 {
        return Err(ToughError::BadSize);
    }
    let k = spec.count;
    let b = spec.bits;
    if k == 0 || bits < 2 * MIN_PRIME_BITS || (b == 0 && k != 1) || (b != 0 && b < MIN_PRIME_BITS) {
        return Err(ToughError::BadSize);
    }
    // Feasibility: 2·∏q_i + 1 must be able to land in [3·2^(bits−2), 2^bits).
    if b != 0 && (k * (b - 1) + 1 >= bits || k * b + 1 < bits) {
        return Err(ToughError::BadSize);
    }
    // (p−1)/2 mod 4: p ≡ 3 (8) -> 1; p ≡ 7 (8) -> 3.
    let t: u64 = if residue_mod8 == 3 { 1 } else { 3 };
    if k >= 2 {
        return sample_from_pool(rng, bits, t, spec, sieve);
    }

    let prec = bits.div_ceil(64) * 64;
    let wide = prec + 64;
    let one = BoxedUint::one_with_precision(wide);
    let lo = BoxedUint::from(3u8).resize(wide).shl(bits - 2);
    let hi = one.shl(bits);
    let lo_m1 = lo.wrapping_sub(&one);
    let hi_m2 = hi.wrapping_sub(BoxedUint::from(2u8));
    let q_floor = if b == 0 {
        BoxedUint::zero_with_precision(wide)
    } else {
        one.shl(b - 1)
    };
    let q_ceil = if b == 0 {
        None
    } else {
        Some(one.shl(b).wrapping_sub(&one))
    };

    'outer: for _ in 0..MAX_PREFIX_ATTEMPTS {
        let mut factors: Vec<BoxedUint> = Vec::new();
        for _ in 0..k - 1 {
            let q: BoxedUint = random_prime(rng, Flavor::Any, b);
            if factors.contains(&q) {
                continue 'outer;
            }
            factors.push(q);
        }
        let m = factors
            .iter()
            .fold(one.clone(), |a, q| a.concatenating_mul(q).resize(wide));
        let two_m = m.shl(1);
        let Some(two_m_nz) = Option::<NonZero<BoxedUint>>::from(two_m.to_nz()) else {
            return Err(ToughError::BadSize);
        };
        // Range of the last factor q: 2·m·q + 1 ∈ [lo, hi).
        let (qlo, rem) = lo_m1.div_rem_vartime(&two_m_nz);
        let qlo = if bool::from(rem.is_zero()) {
            qlo
        } else {
            qlo.wrapping_add(&one)
        };
        let qhi = hi_m2.div_rem_vartime(&two_m_nz).0;
        let (qlo, qhi) = match &q_ceil {
            Some(c) => (
                if qlo < q_floor { q_floor.clone() } else { qlo },
                if qhi > *c { c.clone() } else { qhi },
            ),
            None => (qlo, qhi),
        };
        if qlo > qhi {
            continue;
        }
        let width = qhi.wrapping_sub(&qlo).wrapping_add(&one);
        let Some(width_nz) = Option::<NonZero<BoxedUint>>::from(width.to_nz()) else {
            continue;
        };
        let m_mod4 = m.as_words()[0] & 3;
        let low2 = (t * m_mod4) & 3; // q ≡ t·m (mod 4) gives q·m ≡ t since m² ≡ 1
        loop {
            let r = BoxedUint::random_mod_vartime(rng, &width_nz);
            let mut q = r.wrapping_add(&qlo);
            // Adjust the two low bits.
            let cur = q.as_words()[0] & 3;
            q = q
                .wrapping_sub(BoxedUint::from(cur))
                .wrapping_add(BoxedUint::from(low2));
            if q < qlo || q > qhi {
                // Possible only at interval edges; draw again.
                continue;
            }
            if divisible_by_small(&q, sieve) {
                continue;
            }
            let p = two_m
                .concatenating_mul(&q)
                .wrapping_add(BoxedUint::one())
                .resize(prec);
            if divisible_by_small(&p, sieve) || factors.contains(&q) {
                continue;
            }
            if !is_prime(Flavor::Any, &p) || !is_prime(Flavor::Any, &q) {
                continue;
            }
            factors.push(q.resize(prec));
            return Ok(ToughPrime { p, factors });
        }
    }
    Err(ToughError::BadSize)
}

/// Samples a tough prime of exactly `bits` bits, `p = 2·∏q_i + 1`, with
/// `p ≡ residue_mod8 (mod 8)`, `residue_mod8 ∈ {3, 7}`. The top two bits of `p` are set.
pub fn sample_tough_prime<R: CryptoRng + ?Sized>(
    rng: &mut R,
    bits: u32,
    residue_mod8: u8,
    spec: ToughSpec,
) -> Result<ToughPrime, ToughError> {
    sample_tough_prime_inner(rng, bits, residue_mod8, spec, &small_primes())
}

/// `SampleRSA` with explicit sizes: `N` has exactly `n_bits` bits (`n_bits` even).
pub fn sample_rsa_with<R: CryptoRng + ?Sized>(
    rng: &mut R,
    n_bits: u32,
    spec: ToughSpec,
) -> Result<RsaModulus, ToughError> {
    if n_bits % 2 != 0 || n_bits < 2 * MIN_PRIME_BITS + 8 {
        return Err(ToughError::BadSize);
    }
    let bits = n_bits / 2;
    let sieve = small_primes();
    let p1 = sample_tough_prime_inner(rng, bits, 3, spec, &sieve)?;
    let h1 = p1.half();
    let p2 = loop {
        let cand = sample_tough_prime_inner(rng, bits, 7, spec, &sieve)?;
        let g = h1.gcd(&cand.half());
        if g.is_one().into() {
            break cand;
        }
    };
    // Both primes are in [3·2^(bits−2), 2^bits), so N has exactly n_bits bits.
    let n = p1.p().concatenating_mul(p2.p());
    if n.bits() != n_bits {
        return Err(ToughError::BadSize);
    }
    Ok(RsaModulus {
        n,
        secret: RsaSecret { p1, p2 },
    })
}

/// `SampleRSA` for the server Paillier modulus (`params.n_rsa` bits, tough primes).
pub fn sample_rsa<R: CryptoRng + ?Sized>(
    rng: &mut R,
    params: &Params,
) -> Result<RsaModulus, ToughError> {
    sample_rsa_with(rng, params.n_rsa, ToughSpec::from_params(params))
}

/// `SampleDF` with explicit sizes: modulus of `n_bits` bits, exponents `λ_i ← [2^{2ℓ}]`.
pub fn sample_df_with<R: CryptoRng + ?Sized>(
    rng: &mut R,
    n_bits: u32,
    spec: ToughSpec,
    ell: u32,
) -> Result<DfTuple, ToughError> {
    if ell == 0 {
        return Err(ToughError::BadSize);
    }
    let rsa = sample_rsa_with(rng, n_bits, spec)?;
    let RsaModulus { n, secret } = rsa;
    let odd = Option::from(n.to_odd()).ok_or(ToughError::BadSize)?;
    let mparams = BoxedMontyParams::new(odd);
    let nz = Option::<NonZero<BoxedUint>>::from(n.to_nz()).ok_or(ToughError::BadSize)?;

    // t = r² for a random unit r.
    let t_form = loop {
        let mut r = BoxedUint::random_mod_vartime(rng, &nz);
        let unit: bool = r.gcd(&n).is_one().into();
        if unit {
            let f = BoxedMontyForm::new(r.clone(), &mparams).square();
            r.zeroize();
            break f;
        }
        r.zeroize();
    };
    let t = t_form.retrieve();

    let exp_bits = 2 * ell;
    let lambda1 = BoxedUint::random_bits(rng, exp_bits);
    let lambda2 = BoxedUint::random_bits(rng, exp_bits);
    let s1 = t_form.pow_bounded_exp(&lambda1, exp_bits).retrieve();
    let s2 = t_form.pow_bounded_exp(&lambda2, exp_bits).retrieve();

    Ok(DfTuple {
        n_hat: n,
        t,
        s1,
        s2,
        secret: DfSecret {
            rsa: secret,
            lambda1,
            lambda2,
        },
    })
}

/// `SampleDF` for the server (`params.n_rsa` bits, tough primes, `ℓ = params.ell`).
pub fn sample_df<R: CryptoRng + ?Sized>(
    rng: &mut R,
    params: &Params,
) -> Result<DfTuple, ToughError> {
    sample_df_with(
        rng,
        params.n_rsa,
        ToughSpec::from_params(params),
        params.ell,
    )
}

/// `SampleDF` for the client's ephemeral tuple (`params.n_client` bits). Tough primes of
/// the server profile do not fit into 1024-bit primes, so safe primes are used.
// TODO(spec §5/§6.2): confirm the client's prime structure with the paper.
pub fn sample_df_client<R: CryptoRng + ?Sized>(
    rng: &mut R,
    params: &Params,
) -> Result<DfTuple, ToughError> {
    // Paper (Algorithm 3): T = ⌈n/4ℓ⌉ primes of 2ℓ bits, same as the server.
    let spec = ToughSpec {
        count: params.n_client.div_ceil(4 * params.ell),
        bits: 2 * params.ell,
    };
    sample_df_with(rng, params.n_client, spec, params.ell)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    extern crate std;
    use super::*;
    use crate::params::PARAMS_128;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    const SPEC: ToughSpec = ToughSpec { count: 4, bits: 64 };

    fn bit_is_set(x: &BoxedUint, i: u32) -> bool {
        bool::from(x.bit(i))
    }

    fn prime(x: &BoxedUint) -> bool {
        is_prime(Flavor::Any, x)
    }

    fn mod8(x: &BoxedUint) -> u64 {
        x.as_words()[0] & 7
    }

    fn check_prime_structure(tp: &ToughPrime, bits: u32, spec: ToughSpec, res: u64) {
        let p = tp.p();
        assert_eq!(p.bits(), bits);
        assert!(bit_is_set(p, bits - 1) && bit_is_set(p, bits - 2));
        assert!(prime(p));
        assert_eq!(mod8(p), res);
        assert_eq!(tp.factors().len(), spec.count as usize);
        for q in tp.factors() {
            if spec.bits != 0 {
                // all but the last factor have exactly `bits` bits; the last one is close
                assert!(q.bits() + 8 >= spec.bits && q.bits() <= spec.bits);
            }
            assert!(prime(q));
        }
        let expect = tp.half().shl(1).wrapping_add(BoxedUint::one());
        assert_eq!(&expect, p);
    }

    #[test]
    fn tough_prime_structure_both_residues() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        for res in [3u8, 7u8] {
            let tp = sample_tough_prime(&mut rng, 256, res, SPEC).unwrap();
            check_prime_structure(&tp, 256, SPEC, res as u64);
        }
    }

    #[test]
    fn safe_prime_when_count_one() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let tp = sample_tough_prime(&mut rng, 128, 7, ToughSpec::SAFE).unwrap();
        check_prime_structure(&tp, 128, ToughSpec::SAFE, 7);
    }

    #[test]
    fn rejects_bad_sizes() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        assert!(sample_tough_prime(&mut rng, 256, 5, SPEC).is_err());
        let big = ToughSpec {
            count: 6,
            bits: 256,
        };
        assert!(sample_tough_prime(&mut rng, 1024, 3, big).is_err());
        assert!(sample_rsa_with(&mut rng, 513, SPEC).is_err());
    }

    #[test]
    fn rsa_small() {
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        let bits = 512;
        let m = sample_rsa_with(&mut rng, bits, SPEC).unwrap();
        assert_eq!(m.n.bits(), bits);
        check_prime_structure(&m.secret.p1, bits / 2, SPEC, 3);
        check_prime_structure(&m.secret.p2, bits / 2, SPEC, 7);
        assert_eq!(m.secret.p1.p().concatenating_mul(m.secret.p2.p()), m.n);
        // gcd(p1-1, p2-1) = 2
        let one = BoxedUint::one();
        let a = m.secret.p1.p().wrapping_sub(&one);
        let b = m.secret.p2.p().wrapping_sub(&one);
        assert_eq!(a.gcd(&b), BoxedUint::from(2u8));
        // small-prime sets disjoint
        for q in m.secret.p1.factors() {
            assert!(!m.secret.p2.factors().contains(q));
        }
        assert!(!alloc::format!("{:?}", m).contains(&alloc::format!("{:x}", m.secret.p1.p())));
        assert_eq!(alloc::format!("{:?}", m.secret), "RsaSecret(***)");
    }

    #[test]
    fn df_small() {
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let ell = 16;
        let d = sample_df_with(&mut rng, 512, SPEC, ell).unwrap();
        assert_eq!(d.n_hat.bits(), 512);
        assert!(d.secret.lambda1.bits() <= 2 * ell && d.secret.lambda2.bits() <= 2 * ell);
        let odd = Option::from(d.n_hat.to_odd()).unwrap();
        let mp = BoxedMontyParams::new(odd);
        let t = BoxedMontyForm::new(d.t.clone(), &mp);
        assert_eq!(t.pow(&d.secret.lambda1).retrieve(), d.s1);
        assert_eq!(t.pow(&d.secret.lambda2).retrieve(), d.s2);
        // t is a square: t^((p-1)/2) = 1 mod each prime, check via QR mod p1 and p2.
        for p in [d.secret.rsa.p1.p(), d.secret.rsa.p2.p()] {
            let pm = Option::from(p.to_odd()).unwrap();
            let pp = BoxedMontyParams::new(pm);
            let tp = BoxedMontyForm::new(d.t.rem(&Option::from(p.to_nz()).unwrap()), &pp);
            let e = p.wrapping_sub(BoxedUint::one()).shr(1);
            assert!(bool::from(tp.pow(&e).retrieve().is_one()));
        }
    }

    #[test]
    #[ignore = "slow in debug: full-size 3072-bit SampleRSA, run with --release"]
    fn rsa_full_size() {
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        let start = std::time::Instant::now();
        let m = sample_rsa(&mut rng, &PARAMS_128).unwrap();
        std::println!("SampleRSA 3072: {:?}", start.elapsed());
        assert_eq!(m.n.bits(), 3072);
        let spec = ToughSpec::from_params(&PARAMS_128);
        check_prime_structure(&m.secret.p1, 1536, spec, 3);
        check_prime_structure(&m.secret.p2, 1536, spec, 7);
        let one = BoxedUint::one();
        let g = m
            .secret
            .p1
            .p()
            .wrapping_sub(&one)
            .gcd(&m.secret.p2.p().wrapping_sub(&one));
        assert_eq!(g, BoxedUint::from(2u8));
    }
}

#[cfg(test)]
mod client_df_tests {
    #![allow(clippy::unwrap_used)]
    extern crate std;
    use super::*;
    use crate::params::PARAMS_128;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    #[ignore = "full-size: run with --release"]
    fn client_df_full_size() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let t = std::time::Instant::now();
        let df = sample_df_client(&mut rng, &PARAMS_128).unwrap();
        std::eprintln!("client DF (2048-bit tough): {:?}", t.elapsed());
        assert_eq!(df.n_hat.bits(), PARAMS_128.n_client);
    }

    #[test]
    #[ignore = "benchmark: run with --release --nocapture"]
    fn bench_median_of_10() {
        let mut c = std::vec::Vec::new();
        let mut r = std::vec::Vec::new();
        for seed in 0..10u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(100 + seed);
            let t = std::time::Instant::now();
            let _ = sample_df_client(&mut rng, &PARAMS_128).unwrap();
            c.push(t.elapsed());
            let t = std::time::Instant::now();
            let _ = sample_rsa(&mut rng, &PARAMS_128).unwrap();
            r.push(t.elapsed());
        }
        c.sort();
        r.sort();
        std::eprintln!(
            "client2048 median {:?} max {:?}; server3072 median {:?} max {:?}",
            c[5],
            c[9],
            r[5],
            r[9]
        );
    }
}
