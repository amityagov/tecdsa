//! Fixed-window precomputation for repeated exponentiations of one base.
use alloc::vec::Vec;
use crypto_bigint::{Choice, ctutils::CtSelect};

use super::{
    monty::{Modulus, Residue},
    sbig::SBig,
};
use crate::error::Result;

/// Table `T[i][d] = base^{d · 2^{w·i}}` for `d ∈ [0, 2^w)`.
pub struct FixedBase {
    modulus: Modulus,
    window: u32,
    table: Vec<Vec<Residue>>,
    max_bits: u32,
}

impl FixedBase {
    /// Builds the table for exponent magnitudes below `2^max_bits`.
    pub fn new(modulus: &Modulus, base: &Residue, max_bits: u32, window: u32) -> Self {
        let window = window.clamp(1, 8);
        let windows = max_bits.div_ceil(window);
        let mut table = Vec::with_capacity(windows as usize);
        let mut g = base.clone();
        for _ in 0..windows {
            let mut row = Vec::with_capacity(1 << window);
            row.push(modulus.one());
            for d in 1..(1usize << window) {
                row.push(row[d - 1].mul(&g));
            }
            // g ← g^{2^w}
            g = row[(1 << window) - 1].mul(&g);
            table.push(row);
        }
        Self {
            modulus: modulus.clone(),
            window,
            table,
            max_bits,
        }
    }

    pub fn max_bits(&self) -> u32 {
        self.max_bits
    }

    /// Approximate memory held by the table, in bytes.
    pub fn size_bytes(&self) -> usize {
        self.table.len() * (1usize << self.window) * (self.modulus.bits_precision() as usize / 8)
    }

    fn digit(mag: &crypto_bigint::BoxedUint, i: u32, w: u32) -> usize {
        let mut d = 0usize;
        for b in 0..w {
            d |= usize::from(mag.bit_vartime(i * w + b)) << b;
        }
        d
    }

    /// Public exponent.
    pub fn pow_vartime(&self, exp: &SBig) -> Result<Residue> {
        let mut acc = self.modulus.one();
        for i in 0..self.table.len() as u32 {
            let d = Self::digit(exp.mag(), i, self.window);
            if d != 0 {
                acc = acc.mul(&self.table[i as usize][d]);
            }
        }
        if bool::from(exp.is_neg()) {
            acc = self.modulus.invert(&acc)?;
        }
        Ok(acc)
    }

    /// Secret exponent: every window is processed, entries are picked by a full scan.
    pub fn pow_ct(&self, exp: &SBig) -> Result<Residue> {
        let mut acc = self.modulus.one();
        for i in 0..self.table.len() {
            let mut d = 0u32;
            for b in 0..self.window {
                d |= u32::from(bool::from(exp.mag().bit(i as u32 * self.window + b))) << b;
            }
            let mut pick = self.table[i][0].as_montgomery().clone();
            for (j, e) in self.table[i].iter().enumerate().skip(1) {
                let hit = Choice::from_u32_eq(d, j as u32);
                pick = pick.ct_select(e.as_montgomery(), hit);
            }
            acc = acc.mul(&Residue::from_montgomery(pick, acc.params()));
        }
        let inv = self.modulus.invert(&acc)?;
        Ok(Residue::from_montgomery(
            acc.as_montgomery()
                .ct_select(inv.as_montgomery(), exp.is_neg()),
            acc.params(),
        ))
    }
}
