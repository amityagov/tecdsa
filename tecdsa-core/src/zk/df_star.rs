//! Π_df* (paper Protocol 9): relaxed proof that `s_i = t^{λ_i}` for the client's ephemeral DF tuple
//! `(M̂, v, u1, u2)` (roles `N̂→M̂`, `t→v`, `s1→u1`, `s2→u2`). `r_df_star` repetitions, one
//! Fiat–Shamir challenge, two `ℓ0`-bit challenges `(e1, e2)` per repetition.
//!
//! Mask `α ∈ ±2^{2ℓ+2ℓ0+ν}` (paper: `±2^{ℓ0+ν_df*}·max_i 2^{⌈log λ_i⌉}` with `λ_i < 2^{2ℓ}` and
//! `ν_df* = ℓ0 + 64`). The verifier additionally enforces the defensive bound `|z| ≤ 2^{mask+1}`.
use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use rand_core::CryptoRng;
use zeroize::Zeroize;

use super::df::{DfStatement, DfWitness, TBase};
use crate::{
    arith::{
        monty::Residue,
        multiexp::multiexp_vartime,
        sbig::{SBig, SRange},
    },
    error::{Error, Result},
    params::Params,
    transcript::Transcript,
};

/// `α ← ±2^{2ℓ+2ℓ0+ν}`: the paper's implementation note uses `ν_df* = ℓ0 + 64` for this proof, so
/// the mask hides `e₁λ₁ + e₂λ₂` (up to `2ℓ+ℓ0+1` bits) with `ℓ0 + ν − 1` bits to spare.
fn mask_bits(params: &Params) -> u32 {
    2 * params.ell + 2 * params.ell0 + params.nu
}

fn mask_range(params: &Params) -> SRange {
    SRange::pm_pow2(mask_bits(params))
}

/// Response range `±2^{mask+2}`, i.e. `|z| ≤ 2^{mask+1}`.
fn z_range(params: &Params) -> SRange {
    SRange::pm_pow2(mask_bits(params) + 2)
}

fn z_len(params: &Params) -> usize {
    1 + ((mask_bits(params) + 1) as usize).div_ceil(8)
}

fn e_len(params: &Params) -> usize {
    (params.ell0 as usize).div_ceil(8)
}

fn check_params(params: &Params) -> Result<()> {
    if params.ell0 == 0 || params.ell0 > 63 || params.r_df_star == 0 {
        return Err(Error::OutOfRange);
    }
    Ok(())
}

fn base_tx(tx: &Transcript, st: &DfStatement, params: &Params) -> Result<Transcript> {
    let mut t = tx.clone();
    t.append("zk", b"df*");
    st.append_to(&mut t)?;
    t.append_u64("r", u64::from(params.r_df_star));
    t.append_u64("l0", u64::from(params.ell0));
    Ok(t)
}

fn derive(
    t: &Transcript,
    a: &[Residue],
    st: &DfStatement,
    params: &Params,
) -> Result<Vec<[u64; 2]>> {
    let mut t = t.clone();
    for ai in a {
        t.append_residue("A", &st.n_hat, ai)?;
    }
    let mut ch = t.challenge("e");
    Ok((0..a.len())
        .map(|_| [ch.small(params.ell0), ch.small(params.ell0)])
        .collect())
}

/// Proof of (relaxed) correct DF parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DfStarProof {
    pub e: Vec<[u64; 2]>,
    pub z: Vec<SBig>,
}

impl DfStarProof {
    pub fn prove<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        st: &DfStatement,
        w: &DfWitness,
    ) -> Result<Self> {
        check_params(params)?;
        let r = params.r_df_star as usize;
        let (l1, l2) = w.as_sbig(2 * params.ell)?;
        let t0 = base_tx(tx, st, params)?;
        let tb = TBase::new(&st.n_hat, &st.t, mask_bits(params))?;
        let mut alphas: Vec<SBig> = (0..r)
            .map(|_| SBig::random_in(rng, mask_range(params)))
            .collect();
        let a: Result<Vec<Residue>> = alphas.iter().map(|al| tb.pow_ct(al)).collect();
        let a = match a {
            Ok(a) => a,
            Err(e) => {
                alphas.zeroize();
                return Err(e);
            }
        };
        let e = derive(&t0, &a, st, params)?;
        let z: Vec<SBig> = alphas
            .iter()
            .zip(&e)
            .map(|(al, [e1, e2])| {
                al.add(&l1.mul(&SBig::from_uint(BoxedUint::from(*e1))))
                    .add(&l2.mul(&SBig::from_uint(BoxedUint::from(*e2))))
            })
            .collect();
        alphas.zeroize();
        // Honest z always lies in the (twice as wide) verifier range.
        if z.iter().any(|zi| !zi.in_range(z_range(params))) {
            return Err(Error::OutOfRange);
        }
        Ok(Self { e, z })
    }

    pub fn verify(&self, tx: &Transcript, params: &Params, st: &DfStatement) -> Result<()> {
        check_params(params)?;
        let r = params.r_df_star as usize;
        if self.e.len() != r || self.z.len() != r {
            return Err(Error::InvalidEncoding);
        }
        let ebound = 1u64 << params.ell0;
        if self.e.iter().any(|[a, b]| *a >= ebound || *b >= ebound) {
            return Err(Error::OutOfRange);
        }
        if self.z.iter().any(|z| !z.in_range(z_range(params))) {
            return Err(Error::OutOfRange);
        }
        let (s1i, s2i) = st.inverses()?;
        let tb = TBase::new(&st.n_hat, &st.t, mask_bits(params))?;
        let mut a = Vec::with_capacity(r);
        for (zi, [e1, e2]) in self.z.iter().zip(&self.e) {
            // A = t^z · s1^{-e1} · s2^{-e2}
            let (b1, b2) = (
                SBig::from_uint(BoxedUint::from(*e1)),
                SBig::from_uint(BoxedUint::from(*e2)),
            );
            let c = multiexp_vartime(&st.n_hat, &[(&s1i, &b1), (&s2i, &b2)])?;
            a.push(tb.pow_vartime(zi)?.mul(&c));
        }
        let t0 = base_tx(tx, st, params)?;
        if derive(&t0, &a, st, params)? == self.e {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    pub fn encoded_len(params: &Params) -> usize {
        params.r_df_star as usize * (2 * e_len(params) + z_len(params))
    }

    /// Per repetition: `e1` ‖ `e2` (⌈ℓ0/8⌉ bytes each, big-endian) ‖ `z`.
    pub fn encode(&self, params: &Params) -> Result<Vec<u8>> {
        check_params(params)?;
        if self.e.len() != params.r_df_star as usize || self.z.len() != self.e.len() {
            return Err(Error::InvalidEncoding);
        }
        let el = e_len(params);
        let mut out = Vec::with_capacity(Self::encoded_len(params));
        for ([e1, e2], z) in self.e.iter().zip(&self.z) {
            if *e1 >> params.ell0 != 0 || *e2 >> params.ell0 != 0 {
                return Err(Error::OutOfRange);
            }
            out.extend_from_slice(&e1.to_be_bytes()[8 - el..]);
            out.extend_from_slice(&e2.to_be_bytes()[8 - el..]);
            out.extend_from_slice(&z.to_bytes(z_range(params))?);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8], params: &Params) -> Result<Self> {
        check_params(params)?;
        if bytes.len() != Self::encoded_len(params) {
            return Err(Error::InvalidEncoding);
        }
        let el = e_len(params);
        let rd = |b: &[u8]| -> Result<u64> {
            let mut buf = [0u8; 8];
            buf[8 - el..].copy_from_slice(b);
            let v = u64::from_be_bytes(buf);
            if v >> params.ell0 != 0 {
                return Err(Error::OutOfRange);
            }
            Ok(v)
        };
        let mut e = Vec::new();
        let mut z = Vec::new();
        for c in bytes.chunks(2 * el + z_len(params)) {
            e.push([rd(&c[..el])?, rd(&c[el..2 * el])?]);
            z.push(SBig::from_bytes(&c[2 * el..], z_range(params))?);
        }
        Ok(Self { e, z })
    }
}

#[cfg(test)]
mod tests {
    use super::super::df::tests::{small_params, small_stmt};
    use super::*;
    use crate::params::PARAMS_128;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn honest_roundtrip() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(11, &p);
        let tx = Transcript::new("test");
        for _ in 0..5 {
            let pr = DfStarProof::prove(&mut rng, &tx, &p, &st, &w).unwrap();
            pr.verify(&tx, &p, &st).unwrap();
            let enc = pr.encode(&p).unwrap();
            assert_eq!(enc.len(), DfStarProof::encoded_len(&p));
            let q = DfStarProof::decode(&enc, &p).unwrap();
            assert_eq!(pr, q);
            q.verify(&tx, &p, &st).unwrap();
            assert!(DfStarProof::decode(&enc[1..], &p).is_err());
        }
    }

    #[test]
    fn tampering_fails() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(12, &p);
        let tx = Transcript::new("test");
        let pr = DfStarProof::prove(&mut rng, &tx, &p, &st, &w).unwrap();
        for i in 0..pr.e.len() {
            for j in 0..2 {
                let mut b = pr.clone();
                b.e[i][j] ^= 1;
                assert!(b.verify(&tx, &p, &st).is_err());
                let mut b = pr.clone();
                b.e[i][j] = 1 << p.ell0;
                assert_eq!(b.verify(&tx, &p, &st), Err(Error::OutOfRange));
            }
            for d in [1i64, -1] {
                let mut b = pr.clone();
                b.z[i] = b.z[i].add(&SBig::from_i64(d));
                assert!(b.verify(&tx, &p, &st).is_err());
            }
        }
        // z range boundary: 2^{n+1} ok range-wise (fails equation), 2^{n+1}+1 out of range
        let n = mask_bits(&p) + 1;
        let edge = SBig::from_uint(BoxedUint::one_with_precision(n + 64).shl(n));
        let mut b = pr.clone();
        b.z[0] = edge.clone();
        assert_eq!(b.verify(&tx, &p, &st), Err(Error::VerificationFailed));
        b.z[0] = edge.add(&SBig::from_i64(1));
        assert_eq!(b.verify(&tx, &p, &st), Err(Error::OutOfRange));
        let mut b = pr.clone();
        b.z.pop();
        assert!(b.verify(&tx, &p, &st).is_err());
        for which in 0..3 {
            let mut s2 = st.clone();
            match which {
                0 => s2.t = s2.t.mul(&s2.t),
                1 => s2.s1 = s2.s1.mul(&s2.t),
                _ => s2.s2 = s2.s2.mul(&s2.t),
            }
            assert!(pr.verify(&tx, &p, &s2).is_err());
        }
        let mut s3 = st.clone();
        s3.t = st.n_hat.residue(&BoxedUint::zero_with_precision(64));
        assert!(pr.verify(&tx, &p, &s3).is_err());
        let mut tx2 = Transcript::new("test");
        tx2.append("x", b"y");
        assert!(pr.verify(&tx2, &p, &st).is_err());
    }

    #[test]
    fn wrong_witness_fails() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(13, &p);
        let tx = Transcript::new("test");
        let one = BoxedUint::one_with_precision(w.lambda2.bits_precision());
        let bad = DfWitness::new(w.lambda1.clone(), w.lambda2.wrapping_add(&one));
        let pr = DfStarProof::prove(&mut rng, &tx, &p, &st, &bad).unwrap();
        assert!(pr.verify(&tx, &p, &st).is_err());
    }

    #[test]
    fn decode_rejects_bad() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(14, &p);
        let tx = Transcript::new("test");
        let enc = DfStarProof::prove(&mut rng, &tx, &p, &st, &w)
            .unwrap()
            .encode(&p)
            .unwrap();
        let mut b = enc.clone();
        b[2] = 2; // sign byte
        assert!(DfStarProof::decode(&b, &p).is_err());
        let mut b = enc.clone();
        b[2] = 0;
        b[3] = 0xff;
        assert!(DfStarProof::decode(&b, &p).is_err());
        // e ≥ 2^ℓ0 with ℓ0 = 4 (one byte holds 8 bits)
        let mut p4 = p;
        p4.ell0 = 4;
        let mut b = alloc::vec![0u8; DfStarProof::encoded_len(&p4)];
        b[0] = 0x10;
        assert!(DfStarProof::decode(&b, &p4).is_err());
    }

    #[test]
    #[ignore]
    fn full_size_timing() {
        extern crate std;
        let p = PARAMS_128;
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let d = crate::rsa::tough::sample_df_client(&mut rng, &p).unwrap();
        let st = DfStatement::client(&d.n_hat, &d.t, &d.s1, &d.s2).unwrap();
        let w = DfWitness::from_secret(&d.secret);
        let tx = Transcript::new("test");
        let t0 = std::time::Instant::now();
        let pr = DfStarProof::prove(&mut rng, &tx, &p, &st, &w).unwrap();
        let t1 = std::time::Instant::now();
        pr.verify(&tx, &p, &st).unwrap();
        let t2 = std::time::Instant::now();
        std::println!(
            "df* prove {:?} verify {:?} size {}",
            t1 - t0,
            t2 - t1,
            pr.encode(&p).unwrap().len()
        );
    }
}
