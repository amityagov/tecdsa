//! Fiat–Shamir transcript with domain separation (spec §10.1) and challenge derivation (§10.3).
use alloc::{string::String, vec::Vec};
use crypto_bigint::{BoxedUint, Gcd, NonZero};
use k256::{
    Scalar,
    elliptic_curve::{bigint::U512, ops::Reduce},
};
use sha2::{Digest, Sha256};

use crate::{
    arith::{
        monty::{Modulus, Residue},
        sbig::{SBig, SRange, resized},
    },
    error::{Error, Result},
};

const PREFIX: &str = "tecdsa-1ole/v1/";

/// Incremental transcript. `Clone` yields an independent fork, so a caller can seed a base
/// transcript with the ssid and public parameters and fork it for every proof.
#[derive(Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    /// Starts a transcript for `domain`, e.g. `zk/sig` (the version prefix is added here).
    pub fn new(domain: &str) -> Self {
        let mut t = Self {
            hasher: Sha256::new(),
        };
        let full: String = [PREFIX, domain].concat();
        t.hasher.update([0x00]);
        t.hasher.update((full.len() as u32).to_be_bytes());
        t.hasher.update(full.as_bytes());
        t
    }

    /// `0x01 ‖ u32be(len(label)) ‖ label ‖ u64be(len(bytes)) ‖ bytes`.
    pub fn append(&mut self, label: &str, bytes: &[u8]) -> &mut Self {
        self.hasher.update([0x01]);
        self.hasher.update((label.len() as u32).to_be_bytes());
        self.hasher.update(label.as_bytes());
        self.hasher.update((bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
        self
    }

    pub fn append_u64(&mut self, label: &str, v: u64) -> &mut Self {
        self.append(label, &v.to_be_bytes())
    }

    /// Big-endian, left-padded to `len` bytes; fails if the value does not fit.
    pub fn append_uint(&mut self, label: &str, x: &BoxedUint, len: usize) -> Result<&mut Self> {
        let bytes = uint_to_be(x, len)?;
        Ok(self.append(label, &bytes))
    }

    /// Residue of `m`, encoded with the fixed width of the modulus.
    pub fn append_residue(&mut self, label: &str, m: &Modulus, x: &Residue) -> Result<&mut Self> {
        let _ = m;
        let len = (x.params().modulus().bits() as usize).div_ceil(8);
        self.append_uint(label, &x.retrieve(), len)
    }

    /// Signed value in the §10.2 format for the interval `range`.
    pub fn append_sbig(&mut self, label: &str, x: &SBig, range: SRange) -> Result<&mut Self> {
        let bytes = x.to_bytes(range)?;
        Ok(self.append(label, &bytes))
    }

    /// Forks the state and derives a challenge stream; the transcript itself is unchanged.
    pub fn challenge(&self, label: &str) -> Challenge {
        let mut h = self.hasher.clone();
        h.update([0x02]);
        h.update((label.len() as u32).to_be_bytes());
        h.update(label.as_bytes());
        let seed: [u8; 32] = h.finalize().into();
        Challenge {
            seed,
            ctr: 0,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

/// Deterministic byte stream `SHA-256(seed ‖ u32be(ctr))`, consumed sequentially.
pub struct Challenge {
    seed: [u8; 32],
    ctr: u32,
    buf: Vec<u8>,
    pos: usize,
}

impl Challenge {
    /// The 32-byte seed (e.g. the commitment `B` of `ro/kg-commit`).
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            if self.pos == self.buf.len() {
                let mut h = Sha256::new();
                h.update(self.seed);
                h.update(self.ctr.to_be_bytes());
                self.ctr = self.ctr.wrapping_add(1);
                self.buf = h.finalize().to_vec();
                self.pos = 0;
            }
            let take = (n - out.len()).min(self.buf.len() - self.pos);
            out.extend_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
        }
        out
    }

    /// Uniform integer below `2^n` (precision `n` rounded up to whole limbs, at least 64).
    pub fn bits(&mut self, n: u32) -> BoxedUint {
        let nbytes = (n as usize).div_ceil(8).max(1);
        let mut b = self.bytes(nbytes);
        let extra = nbytes as u32 * 8 - n;
        if extra > 0 {
            b[0] &= 0xff >> extra;
        }
        let prec = (nbytes as u32 * 8).next_multiple_of(64);
        BoxedUint::from_be_slice(&b, prec).unwrap_or_else(|_| BoxedUint::zero_with_precision(prec))
    }

    /// `e ∈ ±2^ℓ`: `u − 2^{ℓ−1} + 1` for an `ℓ`-bit `u` (§10.3).
    pub fn pm_pow2(&mut self, ell: u32) -> SBig {
        let u = SBig::from_uint(self.bits(ell));
        let shift = SBig::from_uint(
            BoxedUint::one_with_precision(ell.next_multiple_of(64) + 64).shl(ell.saturating_sub(1)),
        );
        u.sub(&shift).add(&SBig::from_i64(1))
    }

    /// `ℓ0`-bit unsigned challenge as a small integer.
    pub fn small(&mut self, n: u32) -> u64 {
        debug_assert!(n <= 64);
        let b = self.bits(n);
        b.as_words()[0]
    }

    /// Scalar of `F_q`: 64 bytes reduced modulo `q`.
    pub fn scalar(&mut self) -> Scalar {
        let b = self.bytes(64);
        <Scalar as Reduce<U512>>::reduce(&U512::from_be_slice(&b))
    }

    /// `y ∈ Z*_M`: `bits(M)+128` bits reduced mod `M`, next block while `gcd(y, M) ≠ 1`.
    pub fn unit_mod(&mut self, m: &Modulus) -> Result<Residue> {
        let nbits = m.modulus().bits();
        for _ in 0..64 {
            let y = self.bits(nbits + 128);
            let mm = resized(m.modulus().as_ref(), y.bits_precision());
            let nz = Option::<NonZero<BoxedUint>>::from(mm.to_nz()).ok_or(Error::InvalidModulus)?;
            let r = y.rem_vartime(&nz);
            let g = r.gcd_vartime(&mm);
            if bool::from(g.is_one()) {
                return Ok(m.residue(&r));
            }
        }
        Err(Error::OutOfRange)
    }

    /// `g ∈ QR_d \ {0, 1}`: value mod `d` from the stream, squared.
    pub fn qr_mod(&mut self, m: &Modulus) -> Result<Residue> {
        let nbits = m.modulus().bits();
        for _ in 0..64 {
            let y = self.bits(nbits + 128);
            let r = m.residue(&y);
            let sq = r.square();
            if !bool::from(sq.is_zero())
                && sq.retrieve() != BoxedUint::one_with_precision(sq.bits_precision())
            {
                return Ok(sq);
            }
        }
        Err(Error::OutOfRange)
    }
}

/// Fixed-length big-endian encoding of a non-negative integer.
pub fn uint_to_be(x: &BoxedUint, len: usize) -> Result<Vec<u8>> {
    let be = x.to_be_bytes();
    if be.len() >= len {
        let (hi, lo) = be.split_at(be.len() - len);
        if hi.iter().any(|b| *b != 0) {
            return Err(Error::OutOfRange);
        }
        Ok(lo.to_vec())
    } else {
        let mut out = alloc::vec![0u8; len - be.len()];
        out.extend_from_slice(&be);
        Ok(out)
    }
}

/// Decodes a fixed-length big-endian integer with at least `bits` of precision.
pub fn uint_from_be(bytes: &[u8], bits: u32) -> Result<BoxedUint> {
    let prec = bits.max(bytes.len() as u32 * 8).next_multiple_of(64);
    BoxedUint::from_be_slice(&pad_left(bytes, prec as usize / 8), prec)
        .map_err(|_| Error::InvalidEncoding)
}

fn pad_left(b: &[u8], len: usize) -> Vec<u8> {
    let mut v = alloc::vec![0u8; len.saturating_sub(b.len())];
    v.extend_from_slice(b);
    v
}
