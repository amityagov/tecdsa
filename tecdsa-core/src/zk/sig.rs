//! Π_sig (paper Protocol 6): well-formedness of the client's signature ciphertext.
//!
//! Statement: `S = enc_N(a; ρ^{λ0}) · E^b mod N²` for known-range `(a, b, λ0)`, together with
//! the group commitment `Ũ = g^a h^b f^γ` and the DF commitment `P̃ = s1^a s2^b t^µ mod N̂`
//! (`(N̂, t, s1, s2)` are the server's DF parameters).
//!
//! Compact proof `(P̃, Ũ, e, z1, z2, w0, w1, w2)`; the verifier reconstructs
//! `Ṽ = g^{z1} h^{z2} f^{w0} · Ũ^{-e}`, `B̃ = s1^{z1} s2^{z2} t^{w1} · P̃^{-e}` and
//! `D = enc_N(z1; ρ^{w2}) · E^{z2} · S^{-e}`.
//! Ranges: `z1 ∈ ±2^{n_a+ε}`, `z2 ∈ ±2^{n_b+ε}`, `w1 ∈ ±2^{n_tρ+ε}`, `w2 ∈ ±2^{n_λ0+ε}`
//! (the mask ranges; honest responses leave them with probability ≈ 2^-ν and the prover restarts).
use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    arith::{
        fixed_base::FixedBase,
        monty::Residue,
        multiexp::multiexp_vartime,
        sbig::{SBig, SRange, resized},
    },
    curve::{
        decode_point, decode_scalar, encode_point, encode_scalar, random_nonzero_scalar,
        sbig_to_scalar,
    },
    df::DfParams,
    error::{Error, Result},
    paillier::PaillierPk,
    params::Params,
    transcript::{Transcript, uint_from_be, uint_to_be},
};

const MAX_ATTEMPTS: u32 = 64;

/// Public statement of Π_sig.
pub struct SigStatement<'a> {
    pub h: &'a ProjectivePoint,
    pub f: &'a ProjectivePoint,
    pub pk: &'a PaillierPk,
    /// The server's DF parameters `(N̂, t, s1, s2)`; fixed-base tables are used when built.
    pub df: &'a DfParams,
    /// `E` (mod N²).
    pub e_ct: &'a Residue,
    /// `S` (mod N²).
    pub s_ct: &'a Residue,
    /// Optional fixed-base table for `ρ` (exponents up to `n_λ0 + ε` bits).
    pub rho_table: Option<&'a FixedBase>,
}

/// Secret witness `(a, b, λ0)` with `S = enc_N(a; ρ^{λ0}) · E^b`.
#[derive(ZeroizeOnDrop)]
pub struct SigWitness {
    pub a: SBig,
    pub b: SBig,
    pub lambda0: SBig,
}

impl core::fmt::Debug for SigWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigWitness(***)")
    }
}

/// Compact proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigProof {
    /// `P̃ ∈ Z*_N̂`, canonical (`< N̂`).
    pub p_tilde: BoxedUint,
    /// `Ũ = g^a h^b f^γ`.
    pub u_tilde: ProjectivePoint,
    pub e: SBig,
    pub z1: SBig,
    pub z2: SBig,
    pub w0: Scalar,
    pub w1: SBig,
    pub w2: SBig,
}

fn e_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.ell)
}
fn z1_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_a() + p.eps())
}
fn z2_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_b() + p.eps())
}
fn mu_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_t_rho)
}
fn w1_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_t_rho + p.eps())
}
fn w2_range(p: &Params) -> SRange {
    SRange::pm_pow2(p.n_lambda0() + p.eps())
}
fn sbig_len(r: SRange) -> usize {
    1 + (r.bits().saturating_sub(1) as usize).div_ceil(8).max(1)
}
fn p_len(p: &Params) -> usize {
    (p.n_rsa as usize).div_ceil(8)
}

fn check_params(p: &Params) -> Result<()> {
    if p.ell == 0 || p.ell > 200 || p.n_rsa == 0 {
        return Err(Error::OutOfRange);
    }
    Ok(())
}

fn lt(a: &BoxedUint, b: &BoxedUint) -> bool {
    let bits = a.bits_precision().max(b.bits_precision());
    resized(a, bits).cmp_vartime(resized(b, bits)) == core::cmp::Ordering::Less
}

fn base_tx(tx: &Transcript, st: &SigStatement<'_>, params: &Params) -> Result<Transcript> {
    let mut t = tx.clone();
    t.append("zk", b"sig");
    t.append_u64("n_a", u64::from(params.n_a()));
    t.append_u64("n_b", u64::from(params.n_b()));
    t.append_u64("n_t", u64::from(params.n_t_rho));
    t.append_u64("n_l0", u64::from(params.n_lambda0()));
    t.append("h", &encode_point(st.h));
    t.append("f", &encode_point(st.f));
    let n = st.pk.n();
    t.append_uint("N", n, (n.bits() as usize).div_ceil(8))?;
    t.append_residue("rho", st.pk.mod_n2(), st.pk.rho())?;
    let nh = st.df.modulus();
    t.append_uint(
        "Nh",
        nh.modulus().as_ref(),
        (nh.modulus().bits() as usize).div_ceil(8),
    )?;
    t.append_residue("t", nh, st.df.t())?;
    t.append_residue("s1", nh, st.df.s1())?;
    t.append_residue("s2", nh, st.df.s2())?;
    t.append_residue("E", st.pk.mod_n2(), st.e_ct)?;
    t.append_residue("S", st.pk.mod_n2(), st.s_ct)?;
    Ok(t)
}

#[allow(clippy::too_many_arguments)]
fn derive_e(
    t: &Transcript,
    st: &SigStatement<'_>,
    p_tilde: &Residue,
    u_tilde: &ProjectivePoint,
    v: &ProjectivePoint,
    b: &Residue,
    d: &Residue,
    params: &Params,
) -> Result<SBig> {
    let mut t = t.clone();
    t.append_residue("P", st.df.modulus(), p_tilde)?;
    t.append("U", &encode_point(u_tilde));
    t.append("V", &encode_point(v));
    t.append_residue("B", st.df.modulus(), b)?;
    t.append_residue("D", st.pk.mod_n2(), d)?;
    Ok(t.challenge("e").pm_pow2(params.ell))
}

fn check_statement(st: &SigStatement<'_>, params: &Params) -> Result<()> {
    check_params(params)?;
    if st.df.modulus().modulus().bits() > params.n_rsa {
        return Err(Error::OutOfRange);
    }
    st.pk.check_ciphertext(&st.e_ct.retrieve())?;
    st.pk.check_ciphertext(&st.s_ct.retrieve())?;
    Ok(())
}

/// `ρ^λ` for a secret `λ` of at most `bits` bits, via the table when it is large enough.
fn rho_pow(st: &SigStatement<'_>, lam: &SBig, bits: u32) -> Result<Residue> {
    match st.rho_table {
        Some(t) if bits <= t.max_bits() => t.pow_ct(lam),
        _ => st.pk.mod_n2().pow_ct(st.pk.rho(), lam, bits),
    }
}

/// `enc_N(m; ρ^λ)` for a secret `λ`.
fn enc_rho(st: &SigStatement<'_>, m: &SBig, lam: &SBig, bits: u32) -> Result<Residue> {
    Ok(st.pk.g_pow(m).mul(&rho_pow(st, lam, bits)?))
}

impl SigProof {
    pub fn prove<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        st: &SigStatement<'_>,
        w: &SigWitness,
    ) -> Result<Self> {
        check_statement(st, params)?;
        if !w.a.in_range(SRange::pm_pow2(params.n_a()))
            || !w.b.in_range(SRange::pm_pow2(params.n_b()))
            || !w.lambda0.in_range(SRange::pm_pow2(params.n_lambda0()))
        {
            return Err(Error::OutOfRange);
        }
        let t0 = base_tx(tx, st, params)?;
        let (r1, r2, r3, r4) = (
            z1_range(params),
            z2_range(params),
            w1_range(params),
            w2_range(params),
        );
        let mut mu = SBig::random_in(rng, mu_range(params));
        let mut gamma = random_nonzero_scalar(rng);
        let sa = sbig_to_scalar(&w.a)?;
        let sb = sbig_to_scalar(&w.b)?;
        let u_tilde = ProjectivePoint::GENERATOR * sa + *st.h * sb + *st.f * gamma;
        let p_tilde = st
            .df
            .commit_ct(
                &w.a,
                &w.b,
                &mu,
                [params.n_a(), params.n_b(), mu_range(params).bits()],
            )
            .inspect_err(|_| mu.zeroize())?;

        let mut result = Err(Error::OutOfRange);
        for _ in 0..MAX_ATTEMPTS {
            let mut alpha = SBig::random_in(rng, r1);
            let mut beta = SBig::random_in(rng, r2);
            let mut gp = random_nonzero_scalar(rng);
            let mut mu2 = SBig::random_in(rng, r3);
            let mut lam = SBig::random_in(rng, r4);
            let first = (|| -> Result<(ProjectivePoint, Residue, Residue)> {
                let v = ProjectivePoint::GENERATOR * sbig_to_scalar(&alpha)?
                    + *st.h * sbig_to_scalar(&beta)?
                    + *st.f * gp;
                let b = st
                    .df
                    .commit_ct(&alpha, &beta, &mu2, [r1.bits(), r2.bits(), r3.bits()])?;
                let d = enc_rho(st, &alpha, &lam, r4.bits())?.mul(&st.pk.scale(
                    st.e_ct,
                    &beta,
                    r2.bits(),
                )?);
                Ok((v, b, d))
            })();
            let step = first.and_then(|(v, b, d)| {
                let e = derive_e(&t0, st, &p_tilde, &u_tilde, &v, &b, &d, params)?;
                let se = sbig_to_scalar(&e)?;
                let z1 = alpha.add(&e.mul(&w.a));
                let z2 = beta.add(&e.mul(&w.b));
                let w0 = gp + se * gamma;
                let w1 = mu2.add(&e.mul(&mu));
                let w2 = lam.add(&e.mul(&w.lambda0));
                Ok((e, z1, z2, w0, w1, w2))
            });
            alpha.zeroize();
            beta.zeroize();
            gp.zeroize();
            mu2.zeroize();
            lam.zeroize();
            match step {
                Err(e) => {
                    result = Err(e);
                    break;
                }
                Ok((e, z1, z2, w0, w1, w2)) => {
                    if z1.in_range(r1) && z2.in_range(r2) && w1.in_range(r3) && w2.in_range(r4) {
                        result = Ok(Self {
                            p_tilde: p_tilde.retrieve(),
                            u_tilde,
                            e,
                            z1,
                            z2,
                            w0,
                            w1,
                            w2,
                        });
                        break;
                    }
                }
            }
        }
        mu.zeroize();
        gamma.zeroize();
        result
    }

    pub fn verify(&self, tx: &Transcript, params: &Params, st: &SigStatement<'_>) -> Result<()> {
        check_statement(st, params).map_err(|_| Error::VerificationFailed)?;
        if !self.e.in_range(e_range(params))
            || !self.z1.in_range(z1_range(params))
            || !self.z2.in_range(z2_range(params))
            || !self.w1.in_range(w1_range(params))
            || !self.w2.in_range(w2_range(params))
        {
            return Err(Error::OutOfRange);
        }
        let m = st.df.modulus();
        if !lt(&self.p_tilde, m.modulus().as_ref()) {
            return Err(Error::OutOfRange);
        }
        let p_t = m.residue(&self.p_tilde);
        m.invert(&p_t).map_err(|_| Error::VerificationFailed)?;
        let neg_e = self.e.negate();
        // Ṽ = g^{z1} h^{z2} f^{w0} · Ũ^{-e}
        let v = ProjectivePoint::GENERATOR * sbig_to_scalar(&self.z1)?
            + *st.h * sbig_to_scalar(&self.z2)?
            + *st.f * self.w0
            - self.u_tilde * sbig_to_scalar(&self.e)?;
        // B̃ = s1^{z1} s2^{z2} t^{w1} · P̃^{-e}
        let b = multiexp_vartime(
            m,
            &[
                (st.df.s1(), &self.z1),
                (st.df.s2(), &self.z2),
                (st.df.t(), &self.w1),
                (&p_t, &neg_e),
            ],
        )?;
        // D = (1+N)^{z1} · ρ^{w2} · E^{z2} · S^{-e}
        let d = st.pk.g_pow(&self.z1).mul(&multiexp_vartime(
            st.pk.mod_n2(),
            &[
                (st.pk.rho(), &self.w2),
                (st.e_ct, &self.z2),
                (st.s_ct, &neg_e),
            ],
        )?);
        let t0 = base_tx(tx, st, params)?;
        if derive_e(&t0, st, &p_t, &self.u_tilde, &v, &b, &d, params)? == self.e {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    pub fn encoded_len(params: &Params) -> usize {
        p_len(params)
            + 33
            + sbig_len(e_range(params))
            + sbig_len(z1_range(params))
            + sbig_len(z2_range(params))
            + 32
            + sbig_len(w1_range(params))
            + sbig_len(w2_range(params))
    }

    /// `P̃` (⌈n_rsa/8⌉ bytes) ‖ `Ũ` (33) ‖ `e` ‖ `z1` ‖ `z2` ‖ `w0` (32) ‖ `w1` ‖ `w2`
    /// (signed integers in the spec §10.2 format).
    pub fn encode(&self, params: &Params) -> Result<Vec<u8>> {
        check_params(params)?;
        let mut out = uint_to_be(&self.p_tilde, p_len(params))?;
        out.extend_from_slice(&encode_point(&self.u_tilde));
        out.extend_from_slice(&self.e.to_bytes(e_range(params))?);
        out.extend_from_slice(&self.z1.to_bytes(z1_range(params))?);
        out.extend_from_slice(&self.z2.to_bytes(z2_range(params))?);
        out.extend_from_slice(&encode_scalar(&self.w0));
        out.extend_from_slice(&self.w1.to_bytes(w1_range(params))?);
        out.extend_from_slice(&self.w2.to_bytes(w2_range(params))?);
        Ok(out)
    }

    pub fn decode(bytes: &[u8], params: &Params) -> Result<Self> {
        check_params(params)?;
        if bytes.len() != Self::encoded_len(params) {
            return Err(Error::InvalidEncoding);
        }
        let (pb, rest) = bytes.split_at(p_len(params));
        let p_tilde = uint_from_be(pb, params.n_rsa)?;
        let (ub, rest) = rest.split_at(33);
        let (eb, rest) = rest.split_at(sbig_len(e_range(params)));
        let (z1b, rest) = rest.split_at(sbig_len(z1_range(params)));
        let (z2b, rest) = rest.split_at(sbig_len(z2_range(params)));
        let (w0b, rest) = rest.split_at(32);
        let (w1b, w2b) = rest.split_at(sbig_len(w1_range(params)));
        Ok(Self {
            p_tilde,
            u_tilde: decode_point(ub)?,
            e: SBig::from_bytes(eb, e_range(params))?,
            z1: SBig::from_bytes(z1b, z1_range(params))?,
            z2: SBig::from_bytes(z2b, z2_range(params))?,
            w0: decode_scalar(w0b)?,
            w1: SBig::from_bytes(w1b, w1_range(params))?,
            w2: SBig::from_bytes(w2b, w2_range(params))?,
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
            n_rsa: 512,
            tough_count: 4,
            tough_bits: 64,
            ..PARAMS_128
        }
    }

    struct Fx {
        p: Params,
        pk: PaillierPk,
        df: DfParams,
        h: ProjectivePoint,
        f: ProjectivePoint,
        e_ct: Residue,
        s_ct: Residue,
        w: SigWitness,
    }

    fn make_pk(rng: &mut ChaCha8Rng, n: BoxedUint) -> PaillierPk {
        let n2 = crypto_bigint::ConcatenatingMul::concatenating_mul(&n, &n);
        let m2 = Modulus::new(n2).unwrap();
        let r = m2.residue(&BoxedUint::random_bits(rng, 1000));
        PaillierPk::new(n, &r.square().retrieve()).unwrap()
    }

    fn make_s(pk: &PaillierPk, e_ct: &Residue, p: &Params, w: &SigWitness) -> Residue {
        pk.enc(&w.a, &w.lambda0, p.n_lambda0())
            .unwrap()
            .mul(&pk.scale(e_ct, &w.b, p.n_b()).unwrap())
    }

    fn fixture(seed: u64, p: Params, extremes: bool) -> (Fx, ChaCha8Rng) {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let spec = ToughSpec { count: 4, bits: 64 };
        let d = sample_df_with(&mut rng, p.n_rsa, spec, p.ell).unwrap();
        let m = Modulus::new(d.n_hat.clone()).unwrap();
        let df = DfParams::new(
            m.clone(),
            m.residue(&d.t),
            m.residue(&d.s1),
            m.residue(&d.s2),
        );
        let n = sample_rsa_with(&mut rng, p.n_rsa, spec).unwrap().n;
        let pk = make_pk(&mut rng, n);
        let x = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_x()));
        let beta = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_lambda()));
        let e_ct = pk.enc(&x, &beta, p.n_lambda()).unwrap();
        let mut a = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_a()));
        let mut b = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_b()));
        let mut l0 = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_lambda0()));
        if extremes {
            let top = |n: u32| SBig::from_uint(BoxedUint::one_with_precision(n + 64).shl(n - 1));
            a = top(p.n_a());
            b = top(p.n_b()).negate().add(&SBig::from_i64(1));
            l0 = top(p.n_lambda0());
        }
        let w = SigWitness { a, b, lambda0: l0 };
        let s_ct = make_s(&pk, &e_ct, &p, &w);
        let h = ProjectivePoint::GENERATOR * Scalar::from(12345u64);
        let f = ProjectivePoint::GENERATOR * Scalar::from(777u64);
        (
            Fx {
                p,
                pk,
                df,
                h,
                f,
                e_ct,
                s_ct,
                w,
            },
            rng,
        )
    }

    impl Fx {
        fn st(&self) -> SigStatement<'_> {
            SigStatement {
                h: &self.h,
                f: &self.f,
                pk: &self.pk,
                df: &self.df,
                e_ct: &self.e_ct,
                s_ct: &self.s_ct,
                rho_table: None,
            }
        }
    }

    #[test]
    fn honest_roundtrip() {
        for (seed, ext) in [(1u64, false), (2, true)] {
            let (f, mut rng) = fixture(seed, small_params(), ext);
            let tx = Transcript::new("test");
            for _ in 0..3 {
                let pr = SigProof::prove(&mut rng, &tx, &f.p, &f.st(), &f.w).unwrap();
                pr.verify(&tx, &f.p, &f.st()).unwrap();
                let enc = pr.encode(&f.p).unwrap();
                assert_eq!(enc.len(), SigProof::encoded_len(&f.p));
                let q = SigProof::decode(&enc, &f.p).unwrap();
                assert_eq!(pr, q);
                q.verify(&tx, &f.p, &f.st()).unwrap();
                assert!(SigProof::decode(&enc[1..], &f.p).is_err());
                let mut longer = enc.clone();
                longer.push(0);
                assert!(SigProof::decode(&longer, &f.p).is_err());
            }
        }
    }

    #[test]
    fn tables_give_same_result() {
        let (mut f, mut rng) = fixture(3, small_params(), false);
        let rho_t = FixedBase::new(f.pk.mod_n2(), f.pk.rho(), f.p.n_lambda0() + f.p.eps(), 4);
        let df = DfParams::new(
            f.df.modulus().clone(),
            f.df.t().clone(),
            f.df.s1().clone(),
            f.df.s2().clone(),
        )
        .with_tables(f.p.n_t_rho + f.p.eps(), 3);
        f.df = df;
        let st = SigStatement {
            rho_table: Some(&rho_t),
            ..f.st()
        };
        let tx = Transcript::new("test");
        let pr = SigProof::prove(&mut rng, &tx, &f.p, &st, &f.w).unwrap();
        pr.verify(&tx, &f.p, &st).unwrap();
        pr.verify(&tx, &f.p, &f.st()).unwrap();
    }

    #[test]
    fn tampering_fails() {
        let (f, mut rng) = fixture(4, small_params(), false);
        let tx = Transcript::new("test");
        let pr = SigProof::prove(&mut rng, &tx, &f.p, &f.st(), &f.w).unwrap();
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
            b.w1 = b.w1.add(&d);
            assert!(b.verify(&tx, &f.p, &f.st()).is_err());
            let mut b = pr.clone();
            b.w2 = b.w2.add(&d);
            assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        }
        let mut b = pr.clone();
        b.w0 += Scalar::ONE;
        assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        let mut b = pr.clone();
        b.u_tilde += ProjectivePoint::GENERATOR;
        assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        // P̃ modified / zero / non-canonical
        let mut b = pr.clone();
        b.p_tilde = b
            .p_tilde
            .wrapping_add(BoxedUint::one_with_precision(b.p_tilde.bits_precision()));
        assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        let mut b = pr.clone();
        b.p_tilde = BoxedUint::zero_with_precision(64);
        assert!(b.verify(&tx, &f.p, &f.st()).is_err());
        let mut b = pr.clone();
        b.p_tilde =
            resized(&pr.p_tilde, 640).wrapping_add(resized(f.df.modulus().modulus().as_ref(), 640));
        assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::OutOfRange));
        // boundaries: 2^{n-1} passes the range check (fails equation), 2^{n-1}+1 is out of range
        for which in 0..4 {
            let n = match which {
                0 => f.p.n_a() + f.p.eps(),
                1 => f.p.n_b() + f.p.eps(),
                2 => f.p.n_t_rho + f.p.eps(),
                _ => f.p.n_lambda0() + f.p.eps(),
            };
            let edge = SBig::from_uint(BoxedUint::one_with_precision(n + 64).shl(n - 1));
            let set = |b: &mut SigProof, v: SBig| match which {
                0 => b.z1 = v,
                1 => b.z2 = v,
                2 => b.w1 = v,
                _ => b.w2 = v,
            };
            let mut b = pr.clone();
            set(&mut b, edge.clone());
            assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::VerificationFailed));
            set(&mut b, edge.add(&one));
            assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::OutOfRange));
            set(&mut b, edge.negate().sub(&one));
            assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::OutOfRange));
        }
        let mut b = pr.clone();
        b.e = SBig::from_uint(BoxedUint::one_with_precision(128).shl(f.p.ell - 1)).add(&one);
        assert_eq!(b.verify(&tx, &f.p, &f.st()), Err(Error::OutOfRange));
        // statement fields
        let other = f.h + ProjectivePoint::GENERATOR;
        assert!(
            pr.verify(
                &tx,
                &f.p,
                &SigStatement {
                    h: &other,
                    ..f.st()
                }
            )
            .is_err()
        );
        let other = f.f + ProjectivePoint::GENERATOR;
        assert!(
            pr.verify(
                &tx,
                &f.p,
                &SigStatement {
                    f: &other,
                    ..f.st()
                }
            )
            .is_err()
        );
        let g1 = f.pk.g_pow(&one);
        let e2 = f.e_ct.mul(&g1);
        assert!(
            pr.verify(
                &tx,
                &f.p,
                &SigStatement {
                    e_ct: &e2,
                    ..f.st()
                }
            )
            .is_err()
        );
        let s2 = f.s_ct.mul(&g1);
        assert!(
            pr.verify(
                &tx,
                &f.p,
                &SigStatement {
                    s_ct: &s2,
                    ..f.st()
                }
            )
            .is_err()
        );
        let s3 = f.pk.mod_n2().residue(f.pk.n());
        assert!(
            pr.verify(
                &tx,
                &f.p,
                &SigStatement {
                    s_ct: &s3,
                    ..f.st()
                }
            )
            .is_err()
        );
        let pk2 = make_pk(&mut rng, f.pk.n().clone());
        assert!(
            pr.verify(&tx, &f.p, &SigStatement { pk: &pk2, ..f.st() })
                .is_err()
        );
        let m = f.df.modulus();
        for which in 0..3 {
            let (t, s1, s2) = (f.df.t().clone(), f.df.s1().clone(), f.df.s2().clone());
            let df = match which {
                0 => DfParams::new(m.clone(), t.mul(&t), s1, s2),
                1 => DfParams::new(m.clone(), t.clone(), s1.mul(&t), s2),
                _ => DfParams::new(m.clone(), t, s1.clone(), s1),
            };
            assert!(
                pr.verify(&tx, &f.p, &SigStatement { df: &df, ..f.st() })
                    .is_err()
            );
        }
        // transcript
        let mut tx2 = Transcript::new("test");
        tx2.append("x", b"y");
        assert!(pr.verify(&tx2, &f.p, &f.st()).is_err());
    }

    #[test]
    fn wrong_witness_and_ranges() {
        let (f, mut rng) = fixture(5, small_params(), false);
        let tx = Transcript::new("test");
        let one = SBig::from_i64(1);
        let wit = |a: SBig, b: SBig, l: SBig| SigWitness { a, b, lambda0: l };
        let (a, b, l) = (f.w.a.clone(), f.w.b.clone(), f.w.lambda0.clone());
        for bad in [
            wit(a.add(&one), b.clone(), l.clone()),
            wit(a.clone(), b.add(&one), l.clone()),
            wit(a.clone(), b.clone(), l.add(&one)),
        ] {
            let pr = SigProof::prove(&mut rng, &tx, &f.p, &f.st(), &bad).unwrap();
            assert!(pr.verify(&tx, &f.p, &f.st()).is_err());
        }
        // mismatched S
        let s_bad = f.s_ct.mul(&f.pk.g_pow(&one));
        let st = SigStatement {
            s_ct: &s_bad,
            ..f.st()
        };
        let pr = SigProof::prove(&mut rng, &tx, &f.p, &st, &f.w).unwrap();
        assert!(pr.verify(&tx, &f.p, &st).is_err());
        // out of range witnesses
        let big =
            |n: u32| SBig::from_uint(BoxedUint::one_with_precision(n + 64).shl(n - 1)).add(&one);
        for bad in [
            wit(big(f.p.n_a()), b.clone(), l.clone()),
            wit(a.clone(), big(f.p.n_b()), l.clone()),
            wit(a.clone(), b.clone(), big(f.p.n_lambda0())),
            wit(a.clone(), b.clone(), big(f.p.n_lambda0()).negate()),
        ] {
            assert!(SigProof::prove(&mut rng, &tx, &f.p, &f.st(), &bad).is_err());
        }
    }

    #[test]
    fn decode_rejects_bad() {
        let (f, mut rng) = fixture(6, small_params(), false);
        let tx = Transcript::new("test");
        let p = f.p;
        let enc = SigProof::prove(&mut rng, &tx, &p, &f.st(), &f.w)
            .unwrap()
            .encode(&p)
            .unwrap();
        let o = p_len(&p) + 33;
        let mut b = enc.clone();
        b[o] = 2;
        assert!(SigProof::decode(&b, &p).is_err());
        let el = sbig_len(e_range(&p));
        let mut b = enc.clone();
        b[o] = 1;
        for v in b[o + 1..o + el].iter_mut() {
            *v = 0;
        }
        assert!(SigProof::decode(&b, &p).is_err());
        // w0 non-canonical (all 0xff)
        let o2 = enc.len() - sbig_len(w1_range(&p)) - sbig_len(w2_range(&p)) - 32;
        let mut b = enc.clone();
        for v in b[o2..o2 + 32].iter_mut() {
            *v = 0xff;
        }
        assert!(SigProof::decode(&b, &p).is_err());
        // invalid point
        let mut b = enc.clone();
        b[p_len(&p)] = 0x05;
        assert!(SigProof::decode(&b, &p).is_err());
    }

    #[test]
    #[ignore]
    fn full_size_timing() {
        use crate::setup::server_setup;
        use std::time::Instant;
        let p = PARAMS_128;
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let (data, _sk) = server_setup(&mut rng, &p, [1u8; 32], b"srv").unwrap();
        let vs = data.assume_verified(&p).unwrap();
        let pk = vs.paillier_pk().clone();
        let x = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_x()));
        let beta = SBig::random_in(&mut rng, SRange::pm_pow2(p.n_lambda()));
        let e_ct = pk.enc(&x, &beta, p.n_lambda()).unwrap();
        let top = |n: u32| SBig::from_uint(BoxedUint::one_with_precision(n + 64).shl(n - 1));
        let w = SigWitness {
            a: top(p.n_a()),
            b: top(p.n_b()).negate().add(&SBig::from_i64(1)),
            lambda0: top(p.n_lambda0()),
        };
        let s_ct = make_s(&pk, &e_ct, &p, &w);
        let tx = Transcript::new("test");
        let run = |vs: &crate::setup::VerifiedSetup, label: &str, rng: &mut ChaCha8Rng| {
            let st = SigStatement {
                h: vs.h(),
                f: vs.f(),
                pk: vs.paillier_pk(),
                df: vs.df(),
                e_ct: &e_ct,
                s_ct: &s_ct,
                rho_table: vs.rho_table(),
            };
            let t0 = Instant::now();
            let pr = SigProof::prove(rng, &tx, &p, &st, &w).unwrap();
            let t1 = Instant::now();
            pr.verify(&tx, &p, &st).unwrap();
            let t2 = Instant::now();
            let enc = pr.encode(&p).unwrap();
            std::println!(
                "sig [{label}] prove {:?} verify {:?} size {} (P {} e {} z1 {} z2 {} w1 {} w2 {})",
                t1 - t0,
                t2 - t1,
                enc.len(),
                p_len(&p),
                sbig_len(e_range(&p)),
                sbig_len(z1_range(&p)),
                sbig_len(z2_range(&p)),
                sbig_len(w1_range(&p)),
                sbig_len(w2_range(&p)),
            );
        };
        run(&vs, "no tables", &mut rng);
        let vs = vs.with_tables();
        run(&vs, "default tables", &mut rng);
    }
}
