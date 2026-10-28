//! Paillier encryption with `g = 1 + N` and small randomizers `ρ^λ`.
use crypto_bigint::{BoxedUint, ConcatenatingMul, Gcd, NonZero};
use zeroize::ZeroizeOnDrop;

use crate::arith::{
    monty::{Modulus, Residue},
    sbig::{SBig, resized},
};
use crate::error::{Error, Result};

/// Public key with the server's `ρ = ρ₀^{2N} mod N²` (spec FR-S3).
#[derive(Clone, Debug)]
pub struct PaillierPk {
    n: BoxedUint,
    mod_n: Modulus,
    mod_n2: Modulus,
    rho: Residue,
}

impl PaillierPk {
    pub fn new(n: BoxedUint, rho: &BoxedUint) -> Result<Self> {
        let n2 = n.concatenating_mul(&n);
        let mod_n = Modulus::new(n.clone())?;
        let mod_n2 = Modulus::new(n2)?;
        let rho = mod_n2.residue(rho);
        Ok(Self {
            n,
            mod_n,
            mod_n2,
            rho,
        })
    }

    pub fn n(&self) -> &BoxedUint {
        &self.n
    }
    pub fn mod_n(&self) -> &Modulus {
        &self.mod_n
    }
    pub fn mod_n2(&self) -> &Modulus {
        &self.mod_n2
    }
    pub fn rho(&self) -> &Residue {
        &self.rho
    }

    /// `(1 + mN) mod N²`, i.e. `(1+N)^m` without exponentiation; `m` may be negative.
    pub fn g_pow(&self, m: &SBig) -> Residue {
        let m_mod_n = m.rem_euclid(self.mod_n.modulus());
        let prod = m_mod_n.concatenating_mul(&self.n);
        let one = BoxedUint::one_with_precision(prod.bits_precision());
        self.mod_n2.residue(&prod.wrapping_add(&one))
    }

    /// `enc_N(m; ρ^λ) = (1+N)^m · ρ^λ mod N²` for a secret `λ` below `2^lambda_bits`.
    pub fn enc(&self, m: &SBig, lambda: &SBig, lambda_bits: u32) -> Result<Residue> {
        let r = self.mod_n2.pow_ct(&self.rho, lambda, lambda_bits)?;
        Ok(self.g_pow(m).mul(&r))
    }

    /// `c^v` for a secret exponent (homomorphic scalar multiplication).
    pub fn scale(&self, c: &Residue, v: &SBig, v_bits: u32) -> Result<Residue> {
        self.mod_n2.pow_ct(c, v, v_bits)
    }

    /// Checks `c ∈ Z*_{N²}`: `0 < c < N²` and `gcd(c, N) = 1`.
    pub fn check_ciphertext(&self, c: &BoxedUint) -> Result<Residue> {
        let n2 = self.mod_n2.modulus();
        if bool::from(c.is_zero()) || c.cmp_vartime(n2.as_ref()) != core::cmp::Ordering::Less {
            return Err(Error::OutOfRange);
        }
        let bits = c.bits_precision().max(self.n.bits_precision());
        let g = resized(c, bits).gcd_vartime(&resized(&self.n, bits));
        if !bool::from(g.is_one()) {
            return Err(Error::NotInvertible);
        }
        Ok(self.mod_n2.residue(c))
    }
}

/// Secret key with precomputed CRT data.
#[derive(ZeroizeOnDrop)]
pub struct PaillierSk {
    p: BoxedUint,
    q: BoxedUint,
    #[zeroize(skip)]
    mod_p2: Modulus,
    #[zeroize(skip)]
    mod_q2: Modulus,
    #[zeroize(skip)]
    mod_p: Modulus,
    #[zeroize(skip)]
    mod_q: Modulus,
    /// `((p−1)·q)^{-1} mod p`
    hp: BoxedUint,
    /// `((q−1)·p)^{-1} mod q`
    hq: BoxedUint,
    /// `q^{-1} mod p`
    q_inv_p: BoxedUint,
}

impl core::fmt::Debug for PaillierSk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PaillierSk(***)")
    }
}

impl PaillierSk {
    pub fn new(p: BoxedUint, q: BoxedUint) -> Result<Self> {
        let bits = p.bits_precision().max(q.bits_precision());
        let (p, q) = (resized(&p, bits), resized(&q, bits));
        let mod_p = Modulus::new(p.clone())?;
        let mod_q = Modulus::new(q.clone())?;
        let mod_p2 = Modulus::new(p.concatenating_mul(&p))?;
        let mod_q2 = Modulus::new(q.concatenating_mul(&q))?;
        let one = BoxedUint::one_with_precision(bits);
        let inv = |m: &Modulus, a: &BoxedUint| -> Result<BoxedUint> {
            Ok(m.invert(&m.residue(a))?.retrieve())
        };
        let pm1 = p.wrapping_sub(&one);
        let qm1 = q.wrapping_sub(&one);
        let hp = inv(
            &mod_p,
            &mod_p.residue(&pm1).mul(&mod_p.residue(&q)).retrieve(),
        )?;
        let hq = inv(
            &mod_q,
            &mod_q.residue(&qm1).mul(&mod_q.residue(&p)).retrieve(),
        )?;
        let q_inv_p = inv(&mod_p, &q)?;
        Ok(Self {
            p,
            q,
            mod_p2,
            mod_q2,
            mod_p,
            mod_q,
            hp,
            hq,
            q_inv_p,
        })
    }

    /// Decrypts `c ∈ Z*_{N²}` into `[0, N)` by CRT over `p²` and `q²`.
    pub fn dec(&self, c: &Residue) -> Result<BoxedUint> {
        let cb = c.retrieve();
        let mp = self.dec_prime(&cb, &self.p, &self.mod_p2, &self.mod_p, &self.hp)?;
        let mq = self.dec_prime(&cb, &self.q, &self.mod_q2, &self.mod_q, &self.hq)?;
        // m = mq + q · ((mp − mq)·q^{-1} mod p)
        let diff = self.mod_p.residue(&mp).sub(&self.mod_p.residue(&mq));
        let t = diff.mul(&self.mod_p.residue(&self.q_inv_p)).retrieve();
        let n_bits = self.p.bits_precision() * 2;
        let m = t
            .concatenating_mul(&self.q)
            .wrapping_add(resized(&mq, n_bits));
        Ok(m)
    }

    fn dec_prime(
        &self,
        c: &BoxedUint,
        p: &BoxedUint,
        mod_p2: &Modulus,
        mod_p: &Modulus,
        h: &BoxedUint,
    ) -> Result<BoxedUint> {
        let one = BoxedUint::one_with_precision(p.bits_precision());
        let pm1 = p.wrapping_sub(&one);
        let u = mod_p2.pow_ct(
            &mod_p2.residue(c),
            &SBig::from_uint(pm1.clone()),
            pm1.bits_precision(),
        )?;
        // L(u) = (u − 1) / p
        let ub = u.retrieve();
        let u1 = ub.wrapping_sub(resized(&BoxedUint::one(), ub.bits_precision()));
        let pnz = Option::<NonZero<BoxedUint>>::from(resized(p, ub.bits_precision()).to_nz())
            .ok_or(Error::InvalidModulus)?;
        let l = u1.div_rem(&pnz).0;
        Ok(mod_p.residue(&l).mul(&mod_p.residue(h)).retrieve())
    }
}
