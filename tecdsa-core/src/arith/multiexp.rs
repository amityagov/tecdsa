//! Straus/Shamir simultaneous exponentiation for 2–4 bases (public data only).
use alloc::vec::Vec;

use super::{
    monty::{Modulus, Residue},
    sbig::SBig,
};
use crate::error::{Error, Result};

/// `∏ base_i^{exp_i}` in variable time. At most 4 terms.
pub fn multiexp_vartime(m: &Modulus, terms: &[(&Residue, &SBig)]) -> Result<Residue> {
    let k = terms.len();
    if k == 0 || k > 4 {
        return Err(Error::OutOfRange);
    }
    let mut bases: Vec<Residue> = Vec::with_capacity(k);
    let mut mags = Vec::with_capacity(k);
    let mut max_bits = 0;
    for (b, e) in terms {
        bases.push(if bool::from(e.is_neg()) {
            m.invert(b)?
        } else {
            (*b).clone()
        });
        max_bits = max_bits.max(e.mag().bits_vartime());
        mags.push(e.mag());
    }
    // table[mask] = ∏_{i ∈ mask} base_i
    let mut table: Vec<Residue> = Vec::with_capacity(1 << k);
    table.push(m.one());
    for mask in 1usize..(1 << k) {
        let low = mask.trailing_zeros() as usize;
        table.push(table[mask & (mask - 1)].mul(&bases[low]));
    }
    let mut acc = m.one();
    for bit in (0..max_bits).rev() {
        acc = acc.square();
        let mut mask = 0usize;
        for (i, mag) in mags.iter().enumerate() {
            if mag.bit_vartime(bit) {
                mask |= 1 << i;
            }
        }
        if mask != 0 {
            acc = acc.mul(&table[mask]);
        }
    }
    Ok(acc)
}
