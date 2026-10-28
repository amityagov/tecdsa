//! Π_df (paper Protocol 8): the Damgård–Fujisaki parameters `(N̂, t, s1, s2)` satisfy
//! `s_i = t^{λ_i}` with `λ_i < 2^{2ℓ}`. `r_df` parallel repetitions share one Fiat–Shamir challenge
//! (2 bits per repetition). Compact proof: the challenge bits and the responses `z_i`.
//!
//! Also hosts the statement/witness types and the shared `t`-power helper used by Π_df*.
use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    arith::{
        fixed_base::FixedBase,
        monty::{Modulus, Residue},
        sbig::{SBig, SRange},
    },
    error::{Error, Result},
    params::Params,
    rsa::tough::DfSecret,
    transcript::Transcript,
};

const WINDOW: u32 = 4;
const MAX_RESTARTS: usize = 64;

/// Public DF statement `(N̂, t, s1, s2)`.
#[derive(Clone, Debug)]
pub struct DfStatement {
    pub n_hat: Modulus,
    pub t: Residue,
    pub s1: Residue,
    pub s2: Residue,
}

impl DfStatement {
    pub fn new(n_hat: Modulus, t: Residue, s1: Residue, s2: Residue) -> Self {
        Self { n_hat, t, s1, s2 }
    }

    /// From plain integers (reduced modulo `N̂`).
    pub fn from_uints(
        n_hat: &BoxedUint,
        t: &BoxedUint,
        s1: &BoxedUint,
        s2: &BoxedUint,
    ) -> Result<Self> {
        let m = Modulus::new(n_hat.clone())?;
        let (t, s1, s2) = (m.residue(t), m.residue(s1), m.residue(s2));
        Ok(Self {
            n_hat: m,
            t,
            s1,
            s2,
        })
    }

    /// Client role: `(M̂, v, u1, u2)` ↦ `(N̂, t, s1, s2)`.
    pub fn client(
        m_hat: &BoxedUint,
        v: &BoxedUint,
        u1: &BoxedUint,
        u2: &BoxedUint,
    ) -> Result<Self> {
        Self::from_uints(m_hat, v, u1, u2)
    }

    /// Appends the statement with fixed widths.
    pub(crate) fn append_to(&self, tx: &mut Transcript) -> Result<()> {
        let len = (self.n_hat.modulus().bits() as usize).div_ceil(8);
        tx.append_uint("N", self.n_hat.modulus().as_ref(), len)?;
        tx.append_residue("t", &self.n_hat, &self.t)?;
        tx.append_residue("s1", &self.n_hat, &self.s1)?;
        tx.append_residue("s2", &self.n_hat, &self.s2)?;
        Ok(())
    }

    /// Inverses of `t`, `s1`, `s2`; fails if one is not a unit.
    pub(crate) fn inverses(&self) -> Result<(Residue, Residue)> {
        self.n_hat.invert(&self.t)?;
        Ok((self.n_hat.invert(&self.s1)?, self.n_hat.invert(&self.s2)?))
    }
}

/// Secret exponents `λ1, λ2`.
#[derive(ZeroizeOnDrop)]
pub struct DfWitness {
    pub lambda1: BoxedUint,
    pub lambda2: BoxedUint,
}

impl core::fmt::Debug for DfWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DfWitness(***)")
    }
}

impl DfWitness {
    pub fn new(lambda1: BoxedUint, lambda2: BoxedUint) -> Self {
        Self { lambda1, lambda2 }
    }

    pub fn from_secret(s: &DfSecret) -> Self {
        Self {
            lambda1: s.lambda1.clone(),
            lambda2: s.lambda2.clone(),
        }
    }

    /// Both exponents as signed values, checking `λ_i < 2^{bits}`.
    pub(crate) fn as_sbig(&self, bits: u32) -> Result<(SBig, SBig)> {
        if self.lambda1.bits() > bits || self.lambda2.bits() > bits {
            return Err(Error::OutOfRange);
        }
        Ok((
            SBig::from_uint(self.lambda1.clone()),
            SBig::from_uint(self.lambda2.clone()),
        ))
    }
}

/// Powers of `t` with signed exponents in `±2^n`, via a fixed-base table.
/// Uses `t^z = t^{z+K} · (t^K)^{-1}` with `K = 2^{n−1}` so that no per-call inversion is needed.
pub(crate) struct TBase {
    fb: FixedBase,
    shift: SBig,
    t_inv_shift: Residue,
}

impl TBase {
    pub(crate) fn new(m: &Modulus, t: &Residue, n: u32) -> Result<Self> {
        let fb = FixedBase::new(m, t, n + 1, WINDOW);
        let k =
            SBig::from_uint(BoxedUint::one_with_precision(n.next_multiple_of(64) + 64).shl(n - 1));
        let t_k = fb.pow_vartime(&k)?;
        let t_inv_shift = m.invert(&t_k)?;
        Ok(Self {
            fb,
            shift: k,
            t_inv_shift,
        })
    }

    /// Secret exponent.
    pub(crate) fn pow_ct(&self, z: &SBig) -> Result<Residue> {
        let mut s = z.add(&self.shift);
        let r = self.fb.pow_ct(&s).map(|x| x.mul(&self.t_inv_shift));
        s.zeroize();
        r
    }

    /// Public exponent.
    pub(crate) fn pow_vartime(&self, z: &SBig) -> Result<Residue> {
        Ok(self
            .fb
            .pow_vartime(&z.add(&self.shift))?
            .mul(&self.t_inv_shift))
    }
}

/// Packs 2-bit values little-endian within each byte.
fn pack_bits(vals: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; (2 * vals.len()).div_ceil(8)];
    for (i, v) in vals.iter().enumerate() {
        out[i / 4] |= (v & 3) << (2 * (i % 4));
    }
    out
}

fn unpack_bits(bytes: &[u8], r: usize) -> Result<Vec<u8>> {
    if bytes.len() != (2 * r).div_ceil(8) {
        return Err(Error::InvalidEncoding);
    }
    let out: Vec<u8> = (0..r)
        .map(|i| (bytes[i / 4] >> (2 * (i % 4))) & 3)
        .collect();
    // padding bits must be zero (canonical)
    if pack_bits(&out) != bytes {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}

fn z_range(params: &Params) -> SRange {
    SRange::pm_pow2(2 * params.ell + params.nu)
}

fn z_len(params: &Params) -> usize {
    1 + ((2 * params.ell + params.nu - 1) as usize).div_ceil(8)
}

fn base_tx(tx: &Transcript, st: &DfStatement, params: &Params) -> Result<Transcript> {
    let mut t = tx.clone();
    t.append("zk", b"df");
    st.append_to(&mut t)?;
    t.append_u64("r", u64::from(params.r_df));
    Ok(t)
}

fn derive_bits(t: &Transcript, a: &[Residue], st: &DfStatement) -> Result<Vec<u8>> {
    let mut t = t.clone();
    for ai in a {
        t.append_residue("A", &st.n_hat, ai)?;
    }
    let mut ch = t.challenge("e");
    Ok((0..a.len()).map(|_| ch.small(2) as u8).collect())
}

/// Proof of correct DF parameters. `e[i] = e1 | e2 << 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DfProof {
    pub e: Vec<u8>,
    pub z: Vec<SBig>,
}

impl DfProof {
    pub fn prove<R: CryptoRng + ?Sized>(
        rng: &mut R,
        tx: &Transcript,
        params: &Params,
        st: &DfStatement,
        w: &DfWitness,
    ) -> Result<Self> {
        let r = params.r_df as usize;
        let n = 2 * params.ell + params.nu;
        let (l1, l2) = {
            let (a, b) = w.as_sbig(2 * params.ell)?;
            (a, b)
        };
        let t0 = base_tx(tx, st, params)?;
        let tb = TBase::new(&st.n_hat, &st.t, n)?;
        let range = z_range(params);
        for _ in 0..MAX_RESTARTS {
            let mut alphas: Vec<SBig> = (0..r).map(|_| SBig::random_in(rng, range)).collect();
            let a: Result<Vec<Residue>> = alphas.iter().map(|al| tb.pow_ct(al)).collect();
            let a = match a {
                Ok(a) => a,
                Err(e) => {
                    alphas.zeroize();
                    return Err(e);
                }
            };
            let e = derive_bits(&t0, &a, st)?;
            let mut z = Vec::with_capacity(r);
            let mut ok = true;
            for (al, ei) in alphas.iter().zip(&e) {
                let mut zi = al.clone();
                if ei & 1 != 0 {
                    zi = zi.add(&l1);
                }
                if ei & 2 != 0 {
                    zi = zi.add(&l2);
                }
                ok &= zi.in_range(range);
                z.push(zi);
            }
            alphas.zeroize();
            if ok {
                return Ok(Self { e, z });
            }
            z.zeroize();
        }
        Err(Error::OutOfRange)
    }

    pub fn verify(&self, tx: &Transcript, params: &Params, st: &DfStatement) -> Result<()> {
        let r = params.r_df as usize;
        let n = 2 * params.ell + params.nu;
        if self.e.len() != r || self.z.len() != r || self.e.iter().any(|v| *v > 3) {
            return Err(Error::InvalidEncoding);
        }
        let range = z_range(params);
        if self.z.iter().any(|z| !z.in_range(range)) {
            return Err(Error::OutOfRange);
        }
        let (s1i, s2i) = st.inverses()?;
        let both = s1i.mul(&s2i);
        let one = st.n_hat.one();
        let tb = TBase::new(&st.n_hat, &st.t, n)?;
        let mut a = Vec::with_capacity(r);
        for (zi, ei) in self.z.iter().zip(&self.e) {
            let c = match ei {
                0 => &one,
                1 => &s1i,
                2 => &s2i,
                _ => &both,
            };
            a.push(tb.pow_vartime(zi)?.mul(c));
        }
        let t0 = base_tx(tx, st, params)?;
        if derive_bits(&t0, &a, st)? == self.e {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    pub fn encoded_len(params: &Params) -> usize {
        (2 * params.r_df as usize).div_ceil(8) + params.r_df as usize * z_len(params)
    }

    /// Packed challenge bits ‖ `z_i` (sign byte + ⌈(2ℓ+ν−1)/8⌉ bytes each).
    pub fn encode(&self, params: &Params) -> Result<Vec<u8>> {
        if self.e.len() != params.r_df as usize || self.z.len() != self.e.len() {
            return Err(Error::InvalidEncoding);
        }
        let mut out = pack_bits(&self.e);
        for z in &self.z {
            out.extend_from_slice(&z.to_bytes(z_range(params))?);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8], params: &Params) -> Result<Self> {
        if bytes.len() != Self::encoded_len(params) {
            return Err(Error::InvalidEncoding);
        }
        let r = params.r_df as usize;
        let eb = (2 * r).div_ceil(8);
        let e = unpack_bits(&bytes[..eb], r)?;
        let z = bytes[eb..]
            .chunks(z_len(params))
            .map(|c| SBig::from_bytes(c, z_range(params)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { e, z })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        params::{PARAMS_128, ParamsId},
        rsa::tough::{ToughSpec, sample_df_with},
    };
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    /// Reduced profile: ℓ = 16, ν = 16, 512-bit modulus.
    pub(crate) fn small_params() -> Params {
        Params {
            id: ParamsId::P128,
            ell: 16,
            nu: 16,
            r_df: 16,
            r_df_star: 4,
            ell0: 8,
            ..PARAMS_128
        }
    }

    pub(crate) fn small_stmt(seed: u64, p: &Params) -> (DfStatement, DfWitness, ChaCha8Rng) {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let d = sample_df_with(&mut rng, 512, ToughSpec { count: 4, bits: 64 }, p.ell).unwrap();
        let st = DfStatement::from_uints(&d.n_hat, &d.t, &d.s1, &d.s2).unwrap();
        (st, DfWitness::from_secret(&d.secret), rng)
    }

    #[test]
    fn honest_roundtrip() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(1, &p);
        let tx = Transcript::new("test");
        for _ in 0..5 {
            let pr = DfProof::prove(&mut rng, &tx, &p, &st, &w).unwrap();
            pr.verify(&tx, &p, &st).unwrap();
            let enc = pr.encode(&p).unwrap();
            assert_eq!(enc.len(), DfProof::encoded_len(&p));
            let q = DfProof::decode(&enc, &p).unwrap();
            assert_eq!(pr, q);
            q.verify(&tx, &p, &st).unwrap();
            assert!(DfProof::decode(&enc[1..], &p).is_err());
            let mut longer = enc.clone();
            longer.push(0);
            assert!(DfProof::decode(&longer, &p).is_err());
        }
    }

    #[test]
    fn tampering_fails() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(2, &p);
        let tx = Transcript::new("test");
        let pr = DfProof::prove(&mut rng, &tx, &p, &st, &w).unwrap();
        // flip every challenge position
        for i in 0..pr.e.len() {
            let mut b = pr.clone();
            b.e[i] ^= 1;
            assert!(b.verify(&tx, &p, &st).is_err());
            let mut b = pr.clone();
            b.e[i] ^= 2;
            assert!(b.verify(&tx, &p, &st).is_err());
        }
        // z ± 1
        for i in 0..pr.z.len() {
            for d in [1i64, -1] {
                let mut b = pr.clone();
                b.z[i] = b.z[i].add(&SBig::from_i64(d));
                assert!(b.verify(&tx, &p, &st).is_err());
            }
        }
        // z boundary: 2^{n-1} + 1 is out of range
        let n = 2 * p.ell + p.nu;
        let mut b = pr.clone();
        b.z[0] = SBig::from_uint(BoxedUint::one_with_precision(n + 64).shl(n - 1))
            .add(&SBig::from_i64(1));
        assert_eq!(b.verify(&tx, &p, &st), Err(Error::OutOfRange));
        // lengths
        let mut b = pr.clone();
        b.z.pop();
        assert!(b.verify(&tx, &p, &st).is_err());
        // statement fields
        let m = &st.n_hat;
        let one = m.one();
        for which in 0..3 {
            let mut s2 = st.clone();
            match which {
                0 => s2.t = s2.t.mul(&s2.t),
                1 => s2.s1 = s2.s1.mul(&s2.t),
                _ => s2.s2 = s2.s2.mul(&s2.t),
            }
            assert!(pr.verify(&tx, &p, &s2).is_err());
        }
        // non-units
        let mut s3 = st.clone();
        s3.s1 = m.residue(&BoxedUint::zero_with_precision(64));
        assert!(pr.verify(&tx, &p, &s3).is_err());
        let _ = one;
        // transcript
        let mut tx2 = Transcript::new("test");
        tx2.append("x", b"y");
        assert!(pr.verify(&tx2, &p, &st).is_err());
    }

    #[test]
    fn wrong_witness_fails() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(3, &p);
        let tx = Transcript::new("test");
        let bad = DfWitness::new(
            w.lambda1
                .wrapping_add(BoxedUint::one_with_precision(w.lambda1.bits_precision())),
            w.lambda2.clone(),
        );
        let pr = DfProof::prove(&mut rng, &tx, &p, &st, &bad).unwrap();
        assert!(pr.verify(&tx, &p, &st).is_err());
        // witness too large
        let big = DfWitness::new(
            BoxedUint::one_with_precision(128).shl(2 * p.ell),
            w.lambda2.clone(),
        );
        assert!(DfProof::prove(&mut rng, &tx, &p, &st, &big).is_err());
    }

    #[test]
    fn decode_rejects_bad() {
        let p = small_params();
        let (st, w, mut rng) = small_stmt(4, &p);
        let tx = Transcript::new("test");
        let enc = DfProof::prove(&mut rng, &tx, &p, &st, &w)
            .unwrap()
            .encode(&p)
            .unwrap();
        let eb = (2 * p.r_df as usize).div_ceil(8);
        // bad sign byte
        let mut b = enc.clone();
        b[eb] = 2;
        assert!(DfProof::decode(&b, &p).is_err());
        // magnitude out of range
        let mut b = enc.clone();
        b[eb] = 0;
        b[eb + 1] = 0xff;
        assert!(DfProof::decode(&b, &p).is_err());
        // non-canonical padding: r=16 fills the bytes exactly, so use r=15
        let mut p15 = p;
        p15.r_df = 15;
        let mut e15 = alloc::vec![0u8; DfProof::encoded_len(&p15)];
        e15[3] = 0x40; // padding bit set
        for i in 0..15 {
            e15[4 + i * z_len(&p15)] = 0;
        }
        assert!(DfProof::decode(&e15, &p15).is_err());
    }

    #[test]
    #[ignore]
    fn full_size_timing() {
        extern crate std;
        let p = PARAMS_128;
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let d = crate::rsa::tough::sample_df(&mut rng, &p).unwrap();
        let st = DfStatement::from_uints(&d.n_hat, &d.t, &d.s1, &d.s2).unwrap();
        let w = DfWitness::from_secret(&d.secret);
        let tx = Transcript::new("test");
        let t0 = std::time::Instant::now();
        let pr = DfProof::prove(&mut rng, &tx, &p, &st, &w).unwrap();
        let t1 = std::time::Instant::now();
        pr.verify(&tx, &p, &st).unwrap();
        let t2 = std::time::Instant::now();
        std::println!(
            "df prove {:?} verify {:?} size {}",
            t1 - t0,
            t2 - t1,
            pr.encode(&p).unwrap().len()
        );
    }
}
