//! Signed big integers over `BoxedUint` (sign + magnitude), constant-time where it matters.
use alloc::vec::Vec;
use crypto_bigint::{
    BoxedUint, Choice, ConcatenatingMul, NonZero, RandomBits, Resize,
    ctutils::{CtEq, CtSelect},
    rand_core::Rng,
};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Signed integer `(-1)^neg · mag`. Zero is always stored with `neg = false`.
#[derive(Clone)]
pub struct SBig {
    neg: Choice,
    mag: BoxedUint,
}

impl PartialEq for SBig {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.neg.ct_eq(&other.neg))
            && resized(&self.mag, other.mag.bits_precision())
                == resized(&other.mag, self.mag.bits_precision())
    }
}
impl Eq for SBig {}

impl core::fmt::Debug for SBig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SBig(***)")
    }
}

impl Zeroize for SBig {
    fn zeroize(&mut self) {
        self.mag.zeroize();
        self.neg = Choice::FALSE;
    }
}

/// Interval `±2^n = {−2^{n−1}+1, …, 2^{n−1}}` (spec §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SRange {
    bits: u32,
}

impl SRange {
    /// The interval `±2^n`.
    pub const fn pm_pow2(n: u32) -> Self {
        Self { bits: n }
    }
    pub const fn bits(&self) -> u32 {
        self.bits
    }
}

impl SBig {
    pub fn zero(bits: u32) -> Self {
        Self {
            neg: Choice::FALSE,
            mag: BoxedUint::zero_with_precision(bits.max(1)),
        }
    }

    /// Non-negative value.
    pub fn from_uint(mag: BoxedUint) -> Self {
        Self {
            neg: Choice::FALSE,
            mag,
        }
    }

    pub fn from_i64(v: i64) -> Self {
        let mag = BoxedUint::from(v.unsigned_abs());
        Self {
            neg: neg_flag(v),
            mag,
        }
    }

    pub fn is_neg(&self) -> Choice {
        self.neg
    }

    pub fn mag(&self) -> &BoxedUint {
        &self.mag
    }

    pub fn is_zero(&self) -> Choice {
        self.mag.is_zero()
    }

    pub fn bits_precision(&self) -> u32 {
        self.mag.bits_precision()
    }

    fn widen(&self, bits: u32) -> BoxedUint {
        resized(&self.mag, bits)
    }

    fn from_parts(neg: Choice, mag: BoxedUint) -> Self {
        // Canonical zero: never negative.
        let neg = neg.and(mag.is_zero().not());
        Self { neg, mag }
    }

    pub fn negate(&self) -> Self {
        Self::from_parts(self.neg.not(), self.mag.clone())
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let bits = self.mag.bits_precision().max(rhs.mag.bits_precision()) + 64;
        let a = self.widen(bits);
        let b = rhs.widen(bits);
        let same = self.neg.ct_eq(&rhs.neg);
        let sum = a.wrapping_add(&b);
        let (d_ab, a_lt_b) = a.underflowing_sub(&b);
        let d_ba = b.wrapping_sub(&a);
        // Opposite signs: |a| ≥ |b| keeps the sign of a, otherwise sign of b.
        let diff = d_ab.ct_select(&d_ba, a_lt_b);
        let diff_neg = self.neg.ct_select(&rhs.neg, a_lt_b);
        let mag = diff.ct_select(&sum, same);
        let neg = diff_neg.ct_select(&self.neg, same);
        Self::from_parts(neg, mag)
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.negate())
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let mag = self.mag.concatenating_mul(&rhs.mag);
        Self::from_parts(self.neg.ct_ne(&rhs.neg), mag)
    }

    /// Euclidean remainder in `[0, m)`.
    pub fn rem_euclid(&self, m: &NonZero<BoxedUint>) -> BoxedUint {
        let bits = self.mag.bits_precision().max(m.bits_precision());
        let wm = Option::<NonZero<BoxedUint>>::from(resized(m.as_ref(), bits).to_nz())
            .unwrap_or_else(|| m.clone());
        let r = self.widen(bits).rem(&wm);
        let neg_r = r.neg_mod(&wm);
        let out = r.ct_select(&neg_r, self.neg);
        out.resize(m.bits_precision())
    }

    /// Checks `|z| ≤ 2^{n−1}` (public data).
    pub fn in_range(&self, range: SRange) -> bool {
        if range.bits == 0 {
            return bool::from(self.is_zero());
        }
        let bound = BoxedUint::one_with_precision(range.bits.max(self.mag.bits_precision()) + 1)
            .shl(range.bits - 1);
        let m = self.widen(bound.bits_precision());
        // positive: |z| ≤ 2^{n−1}; negative: |z| ≤ 2^{n−1}−1
        if bool::from(self.neg) {
            m.cmp_vartime(&bound) == core::cmp::Ordering::Less
        } else {
            m.cmp_vartime(&bound) != core::cmp::Ordering::Greater
        }
    }

    /// Uniform sample from `±2^n`: `u − 2^{n−1} + 1` with `u ← [0, 2^n)`.
    pub fn random_in<R: Rng + ?Sized>(rng: &mut R, range: SRange) -> Self {
        let n = range.bits.max(1);
        let prec = n + 64;
        let u = match BoxedUint::try_random_bits_with_precision(rng, n, prec) {
            Ok(u) => u,
            Err(_) => BoxedUint::zero_with_precision(prec),
        };
        let shift = BoxedUint::one_with_precision(prec).shl(n - 1);
        let one = BoxedUint::one_with_precision(prec);
        // v = u + 1 − 2^{n−1}; v ∈ [−2^{n−1}+1, 2^{n−1}]
        let up = u.wrapping_add(&one);
        let (d, under) = up.underflowing_sub(&shift);
        let d_neg = shift.wrapping_sub(&up);
        let mag = d.ct_select(&d_neg, under);
        Self::from_parts(under, mag)
    }

    /// Encodes as sign byte `0x00/0x01` followed by `⌈(n−1)/8⌉` big-endian magnitude bytes (spec §10.2).
    pub fn to_bytes(&self, range: SRange) -> Result<Vec<u8>> {
        if !self.in_range(range) {
            return Err(Error::OutOfRange);
        }
        let len = (range.bits.saturating_sub(1) as usize).div_ceil(8).max(1);
        let be = self.mag.to_be_bytes();
        let mut out = Vec::with_capacity(1 + len);
        out.push(u8::from(bool::from(self.neg)));
        if be.len() >= len {
            out.extend_from_slice(&be[be.len() - len..]);
        } else {
            out.resize(1 + len - be.len(), 0);
            out.extend_from_slice(&be);
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8], range: SRange) -> Result<Self> {
        let len = (range.bits.saturating_sub(1) as usize).div_ceil(8).max(1);
        if bytes.len() != 1 + len {
            return Err(Error::InvalidEncoding);
        }
        let neg = match bytes[0] {
            0 => false,
            1 => true,
            _ => return Err(Error::InvalidEncoding),
        };
        let mag = BoxedUint::from_be_slice(&bytes[1..], (len as u32 * 8).max(64))
            .map_err(|_| Error::InvalidEncoding)?;
        if neg && bool::from(mag.is_zero()) {
            return Err(Error::InvalidEncoding);
        }
        let v = Self {
            neg: Choice::from_u8_lsb(u8::from(neg)),
            mag,
        };
        if !v.in_range(range) {
            return Err(Error::OutOfRange);
        }
        Ok(v)
    }
}

fn neg_flag(v: i64) -> Choice {
    Choice::from_u8_lsb(u8::from(v < 0))
}

/// Copy of `x` with at least `bits` of precision (never narrows).
pub(crate) fn resized(x: &BoxedUint, bits: u32) -> BoxedUint {
    if x.bits_precision() >= bits {
        x.clone()
    } else {
        Resize::resize(x.clone(), bits)
    }
}
