//! Π_dlenc (paper Protocol 7): the Paillier ciphertext `E = (1+N)^x · ρ^λ mod N²` encrypts the
//! discrete log `x` of `X = g^x` (secp256k1), with `x ∈ ±2^{n_x}`, `λ ∈ ±2^{n_λ}`.
//!
//! The client's ephemeral DF tuple `(M̂, v, u1, u2)` (roles `N̂→M̂`, `t→v`, `s1→u1`, `s2→u2`) is
//! used for the auxiliary commitment `P̃ = u1^x · u2^λ · v^µ mod M̂`, `µ ← ±2^{n_client+ν}`.
//!
//! Compact proof `(P̃, e, z1, z2, z3)`; the verifier reconstructs `A = g^{z1} X^{-e}`,
//! `B̃ = u1^{z1} u2^{z2} v^{z3} P̃^{-e}` and `D = (1+N)^{z1} ρ^{z2} E^{-e}`.
//! Ranges: `z1 ∈ ±2^{n_x+ε}`, `z2 ∈ ±2^{n_λ+ε}`, `z3 ∈ ±2^{n_client+ν+ε}` (the mask `µ'` range;
//! honest responses leave these ranges with probability ≈ 2^-ν and the prover then restarts).
use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::df::DfStatement;
use crate::{
    arith::{
        monty::Residue,
        multiexp::multiexp_vartime,
        sbig::{SBig, SRange, resized},
    },
    curve::{encode_point, is_identity},
    error::{Error, Result},
    paillier::PaillierPk,
    params::Params,
    transcript::{Transcript, uint_to_be},
};

const MAX_ATTEMPTS: u32 = 64;

/// Public statement.
pub struct DlencStatement<'a> {
    /// `X = g^x`.
    pub x_pub: &'a ProjectivePoint,
    /// `E = enc_N(x; ρ^λ)` as a residue mod `N²`.
    pub e_ct: &'a Residue,
    pub pk: &'a PaillierPk,
    /// The client's ephemeral DF tuple `(M̂, v, u1, u2)`.
    pub client: &'a DfStatement,
}

/// Secret witness `(x, β)` (paper) i.e. `(x, λ)`.
#[derive(ZeroizeOnDrop)]
pub struct DlencWitness {
    pub x: SBig,
    pub beta: SBig,
}

impl core::fmt::Debug for DlencWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DlencWitness(***)")
    }
}

impl DlencWitness {
    pub fn new(x: SBig, beta: SBig) -> Self {
        Self { x, beta }
    }
}

/// Compact proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlencProof {
    /// `P̃ ∈ Z*_M̂`, canonical (`< M̂`).
    pub p_tilde: BoxedUint,
    pub e: SBig,
    pub z1: SBig,
    pub z2: SBig,
    pub z3: SBig,
}

fn e_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.ell)
}
fn z1_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_x() + p.eps())
}
fn z2_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_lambda() + p.eps())
}
fn mu_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_client + p.nu)
}
fn z3_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_client + p.nu + p.eps())
}
fn sbig_len(r: SRange) -> usize {
    1 + (r.bits().saturating_sub(1) as usize).div_ceil(8).max(1)
}
fn p_len(p: &Params) -> usize {
    (p.n_client as usize).div_ceil(8)
}

fn check_params(p: &Params) -> Result<()> {
    // |e| ≤ 2^{ℓ−1} must be below the group order.
    if p.ell == 0 || p.ell > 200 || p.n_client == 0 {
        return Err(Error::OutOfRange);
    }
    Ok(())
}

/// Signed integer reduced into the scalar field (constant time in the value).
fn sbig_to_scalar(s: &SBig) -> Scalar {
    let mut acc = Scalar::ZERO;
    let c256 = Scalar::from(256u64);
    for b in s.mag().to_be_bytes().iter() {
        acc = acc * c256 + Scalar::from(u64::from(*b));
    }
    if bool::from(s.is_neg()) { -acc } else { acc }
}

fn lt(a: &BoxedUint, b: &BoxedUint) -> bool {
    let bits = a.bits_precision().max(b.bits_precision());
    resized(a, bits).cmp_vartime(resized(b, bits)) == core::cmp::Ordering::Less
}

fn base_tx(tx: &Transcript, st: &DlencStatement<'_>, params: &Params) -> Result<Transcript> {
    let mut t = tx.clone();
    t.append("zk", b"dlenc");
    t.append_u64("n_x", u64::from(params.n_x()));
    t.append_u64("n_l", u64::from(params.n_lambda()));
    t.append("X", &encode_point(st.x_pub));
    let n = st.pk.n();
    t.append_uint("N", n, (n.bits() as usize).div_ceil(8))?;
    t.append_residue("rho", st.pk.mod_n2(), st.pk.rho())?;
    t.append_residue("E", st.pk.mod_n2(), st.e_ct)?;
    st.client.append_to(&mut t)?;
    Ok(t)
}

fn derive_e(
    t: &Transcript,
    st: &DlencStatement<'_>,
    p_tilde: &Residue,
    a: &ProjectivePoint,
    b: &Residue,
    d: &Residue,
    params: &Params,
) -> Result<SBig> {
    let mut t = t.clone();
    t.append_residue("P", &st.client.n_hat, p_tilde)?;
    t.append("A", &encode_point(a));
    t.append_residue("B", &st.client.n_hat, b)?;
    t.append_residue("D", st.pk.mod_n2(), d)?;
    Ok(t.challenge("e").pm_pow2(params.ell))
}

/// Common checks: client modulus size and ciphertext membership.
fn check_statement(st: &DlencStatement<'_>, params: &Params) -> Result<()> {
    check_params(params)?;
    if is_identity(st.x_pub) || st.client.n_hat.modulus().bits() > params.n_client {
        return Err(Error::OutOfRange);
    }
    st.pk.check_ciphertext(&st.e_ct.retrieve())?;
    Ok(())
}

impl DlencProof {
    pub fn prove<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        st: &DlencStatement<'_>,
        w: &DlencWitness,
    ) -> Result<Self> {
        check_statement(st, params)?;
        if !w.x.in_range(SRange::pm_pow2(params.n_x()))
            || !w.beta.in_range(SRange::pm_pow2(params.n_lambda()))
        {
            return Err(Error::OutOfRange);
        }
        let m = &st.client.n_hat;
        let (u1, u2, v) = (&st.client.s1, &st.client.s2, &st.client.t);
        let t0 = base_tx(tx, st, params)?;
        let (r1, r2, r3) = (z1_range(params), z2_range(params), z3_range(params));
        let mut mu = SBig::random_in(rng, mu_range(params));
        let p_tilde = m
            .pow_ct(u1, &w.x, params.n_x())
            .and_then(|a| {
                let b = m.pow_ct(u2, &w.beta, params.n_lambda())?;
                let c = m.pow_ct(v, &mu, mu_range(params).bits())?;
                Ok(a.mul(&b).mul(&c))
            })
            .inspect_err(|_| mu.zeroize())?;

        for _ in 0..MAX_ATTEMPTS {
            let mut alpha = SBig::random_in(rng, r1);
            let mut lam = SBig::random_in(rng, r2);
            let mut mu2 = SBig::random_in(rng, r3);
            let first = (|| -> Result<(ProjectivePoint, Residue, Residue)> {
                let a = ProjectivePoint::GENERATOR * sbig_to_scalar(&alpha);
                let b = m
                    .pow_ct(u1, &alpha, r1.bits())?
                    .mul(&m.pow_ct(u2, &lam, r2.bits())?)
                    .mul(&m.pow_ct(v, &mu2, r3.bits())?);
                let d = st.pk.enc(&alpha, &lam, r2.bits())?;
                Ok((a, b, d))
            })();
            let (a, b, d) = match first {
                Ok(f) => f,
                Err(e) => {
                    alpha.zeroize();
                    lam.zeroize();
                    mu2.zeroize();
                    mu.zeroize();
                    return Err(e);
                }
            };
            let e = derive_e(&t0, st, &p_tilde, &a, &b, &d, params)?;
            let z1 = alpha.add(&e.mul(&w.x));
            let z2 = lam.add(&e.mul(&w.beta));
            let z3 = mu2.add(&e.mul(&mu));
            alpha.zeroize();
            lam.zeroize();
            mu2.zeroize();
            if z1.in_range(r1) && z2.in_range(r2) && z3.in_range(r3) {
                mu.zeroize();
                return Ok(Self {
                    p_tilde: p_tilde.retrieve(),
                    e,
                    z1,
                    z2,
                    z3,
                });
            }
        }
        mu.zeroize();
        Err(Error::OutOfRange)
    }

    pub fn verify(&self, tx: &Transcript, params: &Params, st: &DlencStatement<'_>) -> Result<()> {
        check_statement(st, params).map_err(|_| Error::VerificationFailed)?;
        if !self.e.in_range(e_range(params))
            || !self.z1.in_range(z1_range(params))
            || !self.z2.in_range(z2_range(params))
            || !self.z3.in_range(z3_range(params))
        {
            return Err(Error::OutOfRange);
        }
        let m = &st.client.n_hat;
        if !lt(&self.p_tilde, m.modulus().as_ref()) {
            return Err(Error::OutOfRange);
        }
        let p_t = m.residue(&self.p_tilde);
        m.invert(&p_t).map_err(|_| Error::VerificationFailed)?;
        let neg_e = self.e.negate();
        // A = g^{z1} · X^{-e}
        let a = ProjectivePoint::GENERATOR * sbig_to_scalar(&self.z1)
            - *st.x_pub * sbig_to_scalar(&self.e);
        if is_identity(&a) {
            return Err(Error::VerificationFailed);
        }
        // B̃ = u1^{z1} u2^{z2} v^{z3} P̃^{-e}
        let b = multiexp_vartime(m, &[(&st.client.s1, &self.z1), (&st.client.s2, &self.z2)])?.mul(
            &multiexp_vartime(m, &[(&st.client.t, &self.z3), (&p_t, &neg_e)])?,
        );
        // D = (1+N)^{z1} · ρ^{z2} · E^{-e}
        let d = st.pk.g_pow(&self.z1).mul(&multiexp_vartime(
            st.pk.mod_n2(),
            &[(st.pk.rho(), &self.z2), (st.e_ct, &neg_e)],
        )?);
        let t0 = base_tx(tx, st, params)?;
        if derive_e(&t0, st, &p_t, &a, &b, &d, params)? == self.e {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    pub fn encoded_len(params: &Params) -> usize {
        p_len(params)
            + sbig_len(e_range(params))
            + sbig_len(z1_range(params))
            + sbig_len(z2_range(params))
            + sbig_len(z3_range(params))
    }

    /// `P̃` (⌈n_client/8⌉ bytes, big-endian) ‖ `e` ‖ `z1` ‖ `z2` ‖ `z3` (spec §10.2 signed format).
    pub fn encode(&self, params: &Params) -> Result<Vec<u8>> {
        check_params(params)?;
        let mut out = uint_to_be(&self.p_tilde, p_len(params))?;
        out.extend_from_slice(&self.e.to_bytes(e_range(params))?);
        out.extend_from_slice(&self.z1.to_bytes(z1_range(params))?);
        out.extend_from_slice(&self.z2.to_bytes(z2_range(params))?);
        out.extend_from_slice(&self.z3.to_bytes(z3_range(params))?);
        Ok(out)
    }

    pub fn decode(bytes: &[u8], params: &Params) -> Result<Self> {
        check_params(params)?;
        if bytes.len() != Self::encoded_len(params) {
            return Err(Error::InvalidEncoding);
        }
        let (pb, rest) = bytes.split_at(p_len(params));
        let p_tilde = crate::transcript::uint_from_be(pb, params.n_client)?;
        let (eb, rest) = rest.split_at(sbig_len(e_range(params)));
        let (z1b, rest) = rest.split_at(sbig_len(z1_range(params)));
        let (z2b, z3b) = rest.split_at(sbig_len(z2_range(params)));
        Ok(Self {
            p_tilde,
            e: SBig::from_bytes(eb, e_range(params))?,
            z1: SBig::from_bytes(z1b, z1_range(params))?,
            z2: SBig::from_bytes(z2b, z2_range(params))?,
            z3: SBig::from_bytes(z3b, z3_range(params))?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    extern crate std;
    use super::*;
    use crate::{
        arith::monty::Modulus,
        params::{PARAMS_128, ParamsId},
        rsa::tough::{ToughSpec, sample_df_with, sample_rsa_with},
    };
    use crypto_bigint::RandomBits;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn small_params() -> Params {
        Params {
            id: ParamsId::P128,
            ell: 16,
            nu: 16,
            nu_leak: 16,
            n_client: 512,
            ..PARAMS_128
        }
    }

    struct Fx {
        p: Params,
        pk: PaillierPk,
        client: DfStatement,
        x_pub: ProjectivePoint,
        e_ct: Residue,
        w: DlencWitness,
    }

    fn make_pk(rng: &mut ChaCha8Rng, n: BoxedUint) -> PaillierPk {
        let n2 = crypto_bigint::ConcatenatingMul::concatenating_mul(&n, &n);
        let m2 = Modulus::new(n2).unwrap();
        let r = m2.residue(&BoxedUint::random_bits(rng, 1000));
        PaillierPk::new(n, &r.square().retrieve()).unwrap()
    }

    fn fixture(
        seed: u64,
        p: Params,
        n_bits: u32,
        client: Option<DfStatement>,
        neg: bool,
    ) -> (Fx, ChaCha8Rng) {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let spec = ToughSpec { count: 4, bits: 64 };
        let client = client.unwrap_or_else(|| {
            let d = sample_df_with(&mut rng, p.n_client, spec, p.ell).unwrap();
            DfStatement::from_uints(&d.n_hat, &d.t, &d.s1, &d.s2).unwrap()
        });
        let spec_n = if n_bits == p.n_rsa {
            ToughSpec::from_params(&p)
        } else {
            spec
        };
        let n = sample_rsa_with(&mut rng, n_bits, spec_n).unwrap().n;
        let pk = make_pk(&mut rng, n);
        let x = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_x()));
        let x = if neg && !bool::from(x.is_neg()) {
            x.negate()
        } else {
            x
        };
        let beta = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_lambda()));
        let x_pub = ProjectivePoint::GENERATOR * sbig_to_scalar(&x);
        let e_ct = pk.enc(&x, &beta, p.n_lambda()).unwrap();
        (
            Fx {
                p,
                pk,
                client,
                x_pub,
                e_ct,
                w: DlencWitness::new(x, beta),
            },
            rng,
        )
    }

    impl Fx {
        fn st(&self) -> DlencStatement<'_> {
            DlencStatement {
                x_pub: &self.x_pub,
                e_ct: &self.e_ct,
                pk: &self.pk,
                client: &self.client,
            }
        }
    }

    fn small(seed: u64) -> (Fx, ChaCha8Rng) {
        fixture(seed, small_params(), 512, None, false)
    }

    #[test]
    fn honest_roundtrip() {
        for (seed, neg) in [(1u64, false), (2, true)] {
            let (f, mut rng) = fixture(seed, small_params(), 512, None, neg);
            let tx = Transcript::new("test");
            for _ in 0..4 {
                let pr = DlencProof::prove(&mut rng, &tx, &f.p, &f.st(), &f.w).unwrap();
                pr.verify(&tx, &f.p, &f.st()).unwrap();
                let enc = pr.encode(&f.p).unwrap();
                assert_eq!(enc.len(), DlencProof::encoded_len(&f.p));
                let q = DlencProof::decode(&enc, &f.p).unwrap();
                assert_eq!(pr, q);
                q.verify(&tx, &f.p, &f.st()).unwrap();
                assert!(DlencProof::decode(&enc[1..], &f.p).is_err());
                let mut longer = enc.clone();
                longer.push(0);
                assert!(DlencProof::decode(&longer, &f.p).is_err());
            }
        }
    }

    #[test]
    fn tampering_fails() {
        let (f, mut rng) = small(3);
        let tx = Transcript::new("test");
        let pr = DlencProof::prove(&mut rng, &tx, &f.p, &f.st(), &f.w).unwrap();
        let one = SBig::from_i64(1);
        for d in [one.clone(), one.negate()] {
            let mut b = pr.clone();
            b.e = b.e.add(&d);
            assert!(b.verify(&tx, &f.p, &f.st()).is_err());
            let mut b = pr.clone();
            b.z1 = b.z1.add(&d);
            assert!(b.verify(&tx, &f.p, &f.st()).is_err());
            let mut b = pr.clone();
            b.z2 = b.z2.add(&d);
            assert!(b.verify(&tx, &f.p, &f.st()).is_err());
            let mut b = pr.clone();
            b.z3 = b.z3.add(&d);
            assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        }
        // P̃ modified / non-unit / non-canonical
        let mut b = pr.clone();
        b.p_tilde = b
            .p_tilde
            .wrapping_add(BoxedUint::one_with_precision(b.p_tilde.bits_precision()));
        assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        let mut b = pr.clone();
        b.p_tilde = BoxedUint::zero_with_precision(64);
        assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        let mut b = pr.clone();
        b.p_tilde = pr.p_tilde.wrapping_add(f.client.n_hat.modulus().as_ref());
        assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::OutOfRange));
        // boundaries: 2^{n-1} passes the range check (fails equation), 2^{n-1}+1 is out of range
        for which in 0..3 {
            let n = match which {
                0 => f.p.n_x() + f.p.eps(),
                1 => f.p.n_lambda() + f.p.eps(),
                _ => f.p.n_client + f.p.nu + f.p.eps(),
            };
            let edge = SBig::from_uint(BoxedUint::one_with_precision(n + 64).shl(n - 1));
            let mut b = pr.clone();
            match which {
                0 => b.z1 = edge.clone(),
                1 => b.z2 = edge.clone(),
                _ => b.z3 = edge.clone(),
            }
            assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::VerificationFailed));
            match which {
                0 => b.z1 = edge.add(&one),
                1 => b.z2 = edge.add(&one),
                _ => b.z3 = edge.add(&one),
            }
            assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::OutOfRange));
        }
        let mut b = pr.clone();
        b.e = SBig::from_uint(BoxedUint::one_with_precision(128).shl(f.p.ell - 1)).add(&one);
        assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::OutOfRange));
        // statement fields
        let other = f.x_pub + ProjectivePoint::GENERATOR;
        let st = DlencStatement {
            x_pub: &other,
            ..f.st()
        };
        assert!(pr.verify(&tx, &f.p, &st).is_err());
        let ident = ProjectivePoint::IDENTITY;
        let st = DlencStatement {
            x_pub: &ident,
            ..f.st()
        };
        assert!(pr.verify(&tx, &f.p, &st).is_err());
        let e2 = f.e_ct.mul(&f.pk.g_pow(&one));
        let st = DlencStatement {
            e_ct: &e2,
            ..f.st()
        };
        assert!(pr.verify(&tx, &f.p, &st).is_err());
        // different client tuple fields
        for which in 0..4 {
            let mut c = f.client.clone();
            match which {
                0 => c.t = c.t.mul(&c.t),
                1 => c.s1 = c.s1.mul(&c.t),
                2 => c.s2 = c.s2.mul(&c.t),
                _ => c.s1 = c.s2.clone(),
            }
            let st = DlencStatement {
                client: &c,
                ..f.st()
            };
            assert!(pr.verify(&tx, &f.p, &st).is_err());
        }
        // different rho
        let pk2 = make_pk(&mut rng, f.pk.n().clone());
        let st = DlencStatement { pk: &pk2, ..f.st() };
        assert!(pr.verify(&tx, &f.p, &st).is_err());
        // transcript
        let mut tx2 = Transcript::new("test");
        tx2.append("x", b"y");
        assert!(pr.verify(&tx2, &f.p, &f.st()).is_err());
    }

    #[test]
    fn wrong_witness_fails() {
        let (f, mut rng) = small(4);
        let tx = Transcript::new("test");
        let one = SBig::from_i64(1);
        let bad = DlencWitness::new(f.w.x.add(&one), f.w.beta.clone());
        let pr = DlencProof::prove(&mut rng, &tx, &f.p, &f.st(), &bad).unwrap();
        assert!(pr.verify(&tx, &f.p, &f.st()).is_err());
        let bad = DlencWitness::new(f.w.x.clone(), f.w.beta.add(&one));
        let pr = DlencProof::prove(&mut rng, &tx, &f.p, &f.st(), &bad).unwrap();
        assert!(pr.verify(&tx, &f.p, &f.st()).is_err());
        // witness out of range
        let big = SBig::from_uint(BoxedUint::one_with_precision(512).shl(f.p.n_x()));
        let bad = DlencWitness::new(big, f.w.beta.clone());
        assert!(DlencProof::prove(&mut rng, &tx, &f.p, &f.st(), &bad).is_err());
    }

    #[test]
    fn bad_ciphertext_and_rho() {
        let (f, mut rng) = small(5);
        let tx = Transcript::new("test");
        let pr = DlencProof::prove(&mut rng, &tx, &f.p, &f.st(), &f.w).unwrap();
        // E from a different ρ
        let pk2 = make_pk(&mut rng, f.pk.n().clone());
        let e2 = pk2.enc(&f.w.x, &f.w.beta, f.p.n_lambda()).unwrap();
        let st = DlencStatement {
            e_ct: &e2,
            ..f.st()
        };
        assert!(pr.verify(&tx, &f.p, &st).is_err());
        assert!(
            DlencProof::prove(&mut rng, &tx, &f.p, &st, &f.w)
                .unwrap()
                .verify(&tx, &f.p, &st)
                .is_err()
        );
        // E not coprime to N: a multiple of N
        let e3 = f.pk.mod_n2().residue(f.pk.n());
        let st = DlencStatement {
            e_ct: &e3,
            ..f.st()
        };
        assert!(pr.verify(&tx, &f.p, &st).is_err());
        assert!(DlencProof::prove(&mut rng, &tx, &f.p, &st, &f.w).is_err());
        let e4 = f.pk.mod_n2().residue(&BoxedUint::zero_with_precision(64));
        let st = DlencStatement {
            e_ct: &e4,
            ..f.st()
        };
        assert!(pr.verify(&tx, &f.p, &st).is_err());
    }

    #[test]
    fn decode_rejects_bad() {
        let (f, mut rng) = small(6);
        let tx = Transcript::new("test");
        let p = f.p;
        let enc = DlencProof::prove(&mut rng, &tx, &p, &f.st(), &f.w)
            .unwrap()
            .encode(&p)
            .unwrap();
        let o = p_len(&p);
        // bad sign byte of e
        let mut b = enc.clone();
        b[o] = 2;
        assert!(DlencProof::decode(&b, &p).is_err());
        // negative zero e
        let el = sbig_len(e_range(&p));
        let mut b = enc.clone();
        b[o] = 1;
        for v in b[o + 1..o + el].iter_mut() {
            *v = 0;
        }
        assert!(DlencProof::decode(&b, &p).is_err());
        // z1 magnitude too large
        let mut b = enc.clone();
        b[o + el] = 0;
        b[o + el + 1] = 0xff;
        assert!(DlencProof::decode(&b, &p).is_err());
    }

    #[test]
    #[ignore]
    fn full_size_timing() {
        let p = PARAMS_128;
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let d = crate::rsa::tough::sample_df_client(&mut rng, &p).unwrap();
        let client = DfStatement::client(&d.n_hat, &d.t, &d.s1, &d.s2).unwrap();
        let (f, mut rng) = fixture(10, p, p.n_rsa, Some(client), true);
        let tx = Transcript::new("test");
        let t0 = std::time::Instant::now();
        let pr = DlencProof::prove(&mut rng, &tx, &p, &f.st(), &f.w).unwrap();
        let t1 = std::time::Instant::now();
        pr.verify(&tx, &p, &f.st()).unwrap();
        let t2 = std::time::Instant::now();
        let enc = pr.encode(&p).unwrap();
        std::println!(
            "dlenc prove {:?} verify {:?} size {} (P {} e {} z1 {} z2 {} z3 {})",
            t1 - t0,
            t2 - t1,
            enc.len(),
            p_len(&p),
            sbig_len(e_range(&p)),
            sbig_len(z1_range(&p)),
            sbig_len(z2_range(&p)),
            sbig_len(z3_range(&p)),
        );
    }
}
