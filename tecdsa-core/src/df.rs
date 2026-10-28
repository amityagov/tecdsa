//! Damgård–Fujisaki commitments `∏ base_i^{x_i}` over `Z*_N̂`.
use alloc::vec::Vec;

use crate::arith::{
    fixed_base::FixedBase,
    monty::{Modulus, Residue},
    multiexp::multiexp_vartime,
    sbig::SBig,
};
use crate::error::Result;

/// DF parameters `(N̂, t, s₁, s₂)` with optional fixed-base tables.
pub struct DfParams {
    modulus: Modulus,
    t: Residue,
    s1: Residue,
    s2: Residue,
    tables: Option<[FixedBase; 3]>,
}

impl DfParams {
    pub fn new(modulus: Modulus, t: Residue, s1: Residue, s2: Residue) -> Self {
        Self {
            modulus,
            t,
            s1,
            s2,
            tables: None,
        }
    }

    pub fn modulus(&self) -> &Modulus {
        &self.modulus
    }
    pub fn t(&self) -> &Residue {
        &self.t
    }
    pub fn s1(&self) -> &Residue {
        &self.s1
    }
    pub fn s2(&self) -> &Residue {
        &self.s2
    }

    /// Builds comb tables for `t, s₁, s₂` for exponents below `2^max_bits`.
    pub fn with_tables(mut self, max_bits: u32, window: u32) -> Self {
        let m = &self.modulus;
        self.tables = Some([
            FixedBase::new(m, &self.t, max_bits, window),
            FixedBase::new(m, &self.s1, max_bits, window),
            FixedBase::new(m, &self.s2, max_bits, window),
        ]);
        self
    }

    /// Memory held by precomputed tables, in bytes.
    pub fn tables_size_bytes(&self) -> usize {
        self.tables
            .as_ref()
            .map_or(0, |t| t.iter().map(FixedBase::size_bytes).sum())
    }

    /// `s₁^{a} · s₂^{b} · t^{r}` with secret exponents (prover side).
    pub fn commit_ct(&self, a: &SBig, b: &SBig, r: &SBig, bits: [u32; 3]) -> Result<Residue> {
        let (x, y, z) = match &self.tables {
            Some([_, s1, s2]) if bits[0] <= s1.max_bits() && bits[1] <= s2.max_bits() => {
                (s1.pow_ct(a)?, s2.pow_ct(b)?, self.pow_t_ct(r, bits[2])?)
            }
            _ => (
                self.modulus.pow_ct(&self.s1, a, bits[0])?,
                self.modulus.pow_ct(&self.s2, b, bits[1])?,
                self.modulus.pow_ct(&self.t, r, bits[2])?,
            ),
        };
        Ok(x.mul(&y).mul(&z))
    }

    fn pow_t_ct(&self, r: &SBig, bits: u32) -> Result<Residue> {
        match &self.tables {
            Some([t, _, _]) if bits <= t.max_bits() => t.pow_ct(r),
            _ => self.modulus.pow_ct(&self.t, r, bits),
        }
    }

    /// `s₁^{a} · s₂^{b} · t^{r}` for public exponents (verifier side).
    pub fn commit_vartime(&self, a: &SBig, b: &SBig, r: &SBig) -> Result<Residue> {
        multiexp_vartime(&self.modulus, &[(&self.s1, a), (&self.s2, b), (&self.t, r)])
    }

    /// Residues of the parameters, e.g. for a transcript.
    pub fn elements(&self) -> Vec<&Residue> {
        alloc::vec![&self.t, &self.s1, &self.s2]
    }
}
