//! Server setup and client verification (paper Algorithm 4, spec §6.1 FR-S1..S8).
//!
//! `h, f` are derived from `aux = setup_id ‖ u32be(len(server_id)) ‖ server_id`; the server
//! draws `setup_id` at random. `sid = SHA-256(canonical SetupData bytes)` is the value the
//! application pins (FR-S8).
use alloc::vec::Vec;
use core::cmp::Ordering;
use crypto_bigint::{BoxedUint, ConcatenatingMul, Gcd, Integer, NonZero, RandomMod};
use k256::ProjectivePoint;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    arith::{
        fixed_base::FixedBase,
        monty::Modulus,
        sbig::{SBig, resized},
    },
    curve::{decode_point, derive_h_f, encode_point, is_identity},
    df::DfParams,
    error::{Error, Result},
    paillier::{PaillierPk, PaillierSk},
    params::Params,
    rsa::tough::{sample_df, sample_rsa},
    transcript::{Transcript, uint_from_be, uint_to_be},
    zk::{
        df::{DfProof, DfStatement, DfWitness},
        fac::{FacParams, FacProof, FacWitness},
        modulus::{ModProof, ModWitness},
    },
};

/// Canonical format version (first byte of the encoding).
pub const FORMAT_VERSION: u8 = 0x01;
/// Maximal length of the server identifier.
pub const MAX_SERVER_ID_LEN: usize = 256;
/// Window of the fixed-base table for `ρ`.
pub const RHO_TABLE_WINDOW: u32 = 4;
/// Window of the fixed-base tables for `t, s₁, s₂`.
pub const DF_TABLE_WINDOW: u32 = 3;

/// Public setup of the server (spec §6.1).
#[derive(Clone, Debug)]
pub struct SetupData {
    pub params: Params,
    pub fac: FacParams,
    pub setup_id: [u8; 32],
    pub server_id: Vec<u8>,
    pub n: BoxedUint,
    pub n_hat: BoxedUint,
    pub rho0: BoxedUint,
    pub rho: BoxedUint,
    pub t: BoxedUint,
    pub s1: BoxedUint,
    pub s2: BoxedUint,
    pub h: ProjectivePoint,
    pub f: ProjectivePoint,
    pub pi_mod: ModProof,
    pub pi_fac: FacProof,
    pub pi_df: DfProof,
}

/// Secret output of the server setup. Zeroized on drop (the key zeroizes itself).
#[derive(ZeroizeOnDrop)]
pub struct ServerSetupSecret {
    #[zeroize(skip)]
    sk: PaillierSk,
}

impl core::fmt::Debug for ServerSetupSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServerSetupSecret(***)")
    }
}

/// Version byte of the exported server setup secret.
const SECRET_VERSION: u8 = 0x01;

impl ServerSetupSecret {
    pub fn paillier_sk(&self) -> &PaillierSk {
        &self.sk
    }

    /// Explicit export for a `SecretStore`: `version ‖ p ‖ q`, each `n_rsa/16` bytes.
    pub fn export_secret(&self, params: &Params) -> Result<Zeroizing<Vec<u8>>> {
        let len = nb(params) / 2;
        let (p, q) = self.sk.factors();
        let mut out = Zeroizing::new(Vec::with_capacity(1 + 2 * len));
        out.push(SECRET_VERSION);
        out.extend_from_slice(&Zeroizing::new(uint_to_be(p, len)?));
        out.extend_from_slice(&Zeroizing::new(uint_to_be(q, len)?));
        Ok(out)
    }

    /// Restores the secret exported by [`Self::export_secret`]; rejects it unless `p·q` is the
    /// Paillier modulus `N` of `data`, so a secret cannot be paired with a foreign setup.
    pub fn import_secret(bytes: &[u8], data: &SetupData) -> Result<Self> {
        let len = nb(&data.params) / 2;
        if bytes.len() != 1 + 2 * len || bytes[0] != SECRET_VERSION {
            return Err(Error::InvalidEncoding);
        }
        let bits = len as u32 * 8;
        let p = uint_from_be(&bytes[1..1 + len], bits)?;
        let q = uint_from_be(&bytes[1 + len..], bits)?;
        let sk = PaillierSk::new(p, q)?;
        let (p, q) = sk.factors();
        let n = p.concatenating_mul(q);
        let bits = n.bits_precision().max(data.n.bits_precision());
        if resized(&n, bits).cmp_vartime(resized(&data.n, bits)) != Ordering::Equal {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self { sk })
    }
}

fn nb(params: &Params) -> usize {
    (params.n_rsa as usize).div_ceil(8)
}

fn lt(a: &BoxedUint, b: &BoxedUint) -> bool {
    let bits = a.bits_precision().max(b.bits_precision());
    resized(a, bits).cmp_vartime(resized(b, bits)) == Ordering::Less
}

fn is_unit(a: &BoxedUint, n: &BoxedUint) -> bool {
    let bits = a.bits_precision().max(n.bits_precision());
    bool::from(resized(a, bits).gcd_vartime(&resized(n, bits)).is_one())
}

fn aux(setup_id: &[u8; 32], server_id: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(36 + server_id.len());
    a.extend_from_slice(setup_id);
    a.extend_from_slice(&(server_id.len() as u32).to_be_bytes());
    a.extend_from_slice(server_id);
    a
}

/// Base transcript shared by the three proofs.
fn base_tx(params: &Params, setup_id: &[u8; 32], server_id: &[u8]) -> Transcript {
    let mut tx = Transcript::new("setup");
    tx.append("params_id", &[params.id as u8]);
    tx.append("setup_id", setup_id);
    tx.append("server_id", server_id);
    tx
}

/// `ρ0^{2N} mod N²`.
fn rho_of(n: &BoxedUint, rho0: &BoxedUint) -> Result<BoxedUint> {
    let n2 = Modulus::new(n.concatenating_mul_self())?;
    let exp = resized(n, n.bits_precision() + 64);
    let exp = exp.wrapping_add(&exp);
    let r = n2.pow_vartime(&n2.residue(rho0), &SBig::from_uint(exp))?;
    Ok(r.retrieve())
}

trait SquareExt {
    fn concatenating_mul_self(&self) -> BoxedUint;
}
impl SquareExt for BoxedUint {
    fn concatenating_mul_self(&self) -> BoxedUint {
        crypto_bigint::ConcatenatingMul::concatenating_mul(self, self)
    }
}

/// Server setup with the standard Π_fac group.
pub fn server_setup<R: CryptoRng + ?Sized>(
    rng: &mut R,
    params: &Params,
    setup_id: [u8; 32],
    server_id: &[u8],
) -> Result<(SetupData, ServerSetupSecret)> {
    server_setup_with(rng, params, &FacParams::standard()?, setup_id, server_id)
}

/// Server setup with an explicit Π_fac group (tests).
pub fn server_setup_with<R: CryptoRng + ?Sized>(
    rng: &mut R,
    params: &Params,
    fac: &FacParams,
    setup_id: [u8; 32],
    server_id: &[u8],
) -> Result<(SetupData, ServerSetupSecret)> {
    if server_id.len() > MAX_SERVER_ID_LEN {
        return Err(Error::OutOfRange);
    }
    let tx = base_tx(params, &setup_id, server_id);
    // FR-S1, FR-S2
    let rsa = sample_rsa(rng, params).map_err(|_| Error::InvalidModulus)?;
    let n = rsa.n.clone();
    let (p1, p2) = (rsa.secret.p1.p(), rsa.secret.p2.p());
    let pi_mod = ModProof::prove(rng, &tx, params, &n, &ModWitness { p1, p2 })?;
    let pi_fac = FacProof::prove(rng, &tx, params, fac, &n, &FacWitness { p: p1, q: p2 })?;
    let sk = PaillierSk::new(p1.clone(), p2.clone())?;
    // FR-S3
    let nz = Option::<NonZero<BoxedUint>>::from(n.to_nz()).ok_or(Error::InvalidModulus)?;
    let rho0 = loop {
        let r = BoxedUint::random_mod_vartime(rng, &nz);
        if is_unit(&r, &n) {
            break r;
        }
    };
    let rho = rho_of(&n, &rho0)?;
    // FR-S4: the tuple (with its factorization and λ's) is zeroized when dropped.
    let df = sample_df(rng, params).map_err(|_| Error::InvalidModulus)?;
    let st = DfStatement::from_uints(&df.n_hat, &df.t, &df.s1, &df.s2)?;
    let pi_df = DfProof::prove(rng, &tx, params, &st, &DfWitness::from_secret(&df.secret))?;
    // FR-S5
    let (h, f) = derive_h_f(&aux(&setup_id, server_id))?;
    let data = SetupData {
        params: *params,
        fac: fac.clone(),
        setup_id,
        server_id: server_id.to_vec(),
        n,
        n_hat: df.n_hat.clone(),
        rho0,
        rho,
        t: df.t.clone(),
        s1: df.s1.clone(),
        s2: df.s2.clone(),
        h,
        f,
        pi_mod,
        pi_fac,
        pi_df,
    };
    Ok((data, ServerSetupSecret { sk }))
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(Error::InvalidEncoding)?;
        let s = self.b.get(self.pos..end).ok_or(Error::InvalidEncoding)?;
        self.pos = end;
        Ok(s)
    }
}

impl SetupData {
    /// `aux` seed of `h, f`.
    pub fn aux(&self) -> Vec<u8> {
        aux(&self.setup_id, &self.server_id)
    }

    /// Paillier public key `(N, ρ)`.
    pub fn paillier_pk(&self) -> Result<PaillierPk> {
        PaillierPk::new(self.n.clone(), &self.rho)
    }

    /// Canonical encoding (spec §10.2).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let p = &self.params;
        let len = nb(p);
        if self.server_id.len() > MAX_SERVER_ID_LEN {
            return Err(Error::OutOfRange);
        }
        let mut out = Vec::new();
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.setup_id);
        out.extend_from_slice(&(self.server_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.server_id);
        for v in [&self.n, &self.n_hat, &self.rho0] {
            out.extend_from_slice(&uint_to_be(v, len)?);
        }
        out.extend_from_slice(&uint_to_be(&self.rho, 2 * len)?);
        for v in [&self.t, &self.s1, &self.s2] {
            out.extend_from_slice(&uint_to_be(v, len)?);
        }
        for pt in [&self.h, &self.f] {
            if is_identity(pt) {
                return Err(Error::InvalidEncoding);
            }
            out.extend_from_slice(&encode_point(pt));
        }
        out.extend_from_slice(&self.pi_mod.encode(p.n_rsa)?);
        out.extend_from_slice(&self.pi_fac.encode(p, &self.fac, p.n_rsa)?);
        out.extend_from_slice(&self.pi_df.encode(p)?);
        Ok(out)
    }

    /// `sid = SHA-256(to_bytes())`.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.to_bytes()?).into())
    }

    /// Strict decoding with the standard Π_fac group.
    pub fn from_bytes(bytes: &[u8], params: &Params) -> Result<Self> {
        Self::from_bytes_with(bytes, params, &FacParams::standard()?)
    }

    pub fn from_bytes_with(bytes: &[u8], params: &Params, fac: &FacParams) -> Result<Self> {
        let bad = Error::InvalidEncoding;
        let len = nb(params);
        let mut r = Reader { b: bytes, pos: 0 };
        if r.take(1)?[0] != FORMAT_VERSION {
            return Err(bad);
        }
        let setup_id: [u8; 32] = r.take(32)?.try_into().map_err(|_| bad)?;
        let sl = u16::from_be_bytes(r.take(2)?.try_into().map_err(|_| bad)?) as usize;
        if sl > MAX_SERVER_ID_LEN {
            return Err(bad);
        }
        let server_id = r.take(sl)?.to_vec();
        let fixed = 8 * len + 66;
        let (ml, fl, dl) = (
            ModProof::encoded_len(params, params.n_rsa),
            FacProof::encoded_len(params, fac, params.n_rsa),
            DfProof::encoded_len(params),
        );
        if bytes.len() != r.pos + fixed + ml + fl + dl {
            return Err(bad);
        }
        let mut uint = |l: usize| uint_from_be(r.take(l)?, params.n_rsa);
        let n = uint(len)?;
        let n_hat = uint(len)?;
        let rho0 = uint(len)?;
        let rho = uint(2 * len)?;
        let t = uint(len)?;
        let s1 = uint(len)?;
        let s2 = uint(len)?;
        let h = decode_point(r.take(33)?)?;
        let f = decode_point(r.take(33)?)?;
        let pi_mod = ModProof::decode(r.take(ml)?, params, params.n_rsa)?;
        let pi_fac = FacProof::decode(r.take(fl)?, params, fac, params.n_rsa)?;
        let pi_df = DfProof::decode(r.take(dl)?, params)?;
        let data = Self {
            params: *params,
            fac: fac.clone(),
            setup_id,
            server_id,
            n,
            n_hat,
            rho0,
            rho,
            t,
            s1,
            s2,
            h,
            f,
            pi_mod,
            pi_fac,
            pi_df,
        };
        data.check_basic()?;
        Ok(data)
    }

    /// Cheap structural checks: lengths, sizes, ranges, units.
    fn check_basic(&self) -> Result<()> {
        let fail = Error::VerificationFailed;
        let p = &self.params;
        if self.server_id.len() > MAX_SERVER_ID_LEN {
            return Err(fail);
        }
        for m in [&self.n, &self.n_hat] {
            if m.bits() != p.n_rsa || !bool::from(m.is_odd()) {
                return Err(fail);
            }
        }
        if !lt(&self.rho0, &self.n) || !is_unit(&self.rho0, &self.n) {
            return Err(fail);
        }
        let n2 = self.n.concatenating_mul_self();
        if !lt(&self.rho, &n2) || !is_unit(&self.rho, &self.n) {
            return Err(fail);
        }
        for v in [&self.t, &self.s1, &self.s2] {
            if !lt(v, &self.n_hat) || !is_unit(v, &self.n_hat) {
                return Err(fail);
            }
        }
        Ok(())
    }

    /// Client verification (FR-S7) with the standard Π_fac group.
    pub fn verify(&self, params: &Params) -> Result<VerifiedSetup> {
        self.verify_with(params, &FacParams::standard()?)
    }

    pub fn verify_with(&self, params: &Params, fac: &FacParams) -> Result<VerifiedSetup> {
        let fail = Error::VerificationFailed;
        if self.params != *params {
            return Err(fail);
        }
        self.check_basic()?;
        let (h, f) = derive_h_f(&self.aux()).map_err(|_| fail)?;
        if is_identity(&self.h) || is_identity(&self.f) || self.h != h || self.f != f || h == f {
            return Err(fail);
        }
        let want = rho_of(&self.n, &self.rho0)?;
        let bits = want.bits_precision().max(self.rho.bits_precision());
        if resized(&want, bits) != resized(&self.rho, bits) {
            return Err(fail);
        }
        let tx = base_tx(params, &self.setup_id, &self.server_id);
        self.pi_fac.verify(&tx, params, fac, &self.n)?;
        let st = DfStatement::from_uints(&self.n_hat, &self.t, &self.s1, &self.s2)?;
        self.pi_df.verify(&tx, params, &st)?;
        self.pi_mod.verify(&tx, params, &self.n, params.n_rsa)?;
        let hash = self.hash()?;
        let pk = self.paillier_pk()?;
        let df = DfParams::new(st.n_hat, st.t, st.s1, st.s2);
        Ok(VerifiedSetup {
            pk,
            df,
            h,
            f,
            hash,
            server_id: self.server_id.clone(),
            params: *params,
            rho_table: None,
        })
    }
}

impl SetupData {
    /// For the server's *own* data: builds the verified view without re-checking the proofs.
    /// Never use this on data received from another party.
    pub fn assume_verified(&self, params: &Params) -> Result<VerifiedSetup> {
        if self.params != *params {
            return Err(Error::VerificationFailed);
        }
        self.check_basic()?;
        let st = DfStatement::from_uints(&self.n_hat, &self.t, &self.s1, &self.s2)?;
        Ok(VerifiedSetup {
            pk: self.paillier_pk()?,
            df: DfParams::new(st.n_hat, st.t, st.s1, st.s2),
            h: self.h,
            f: self.f,
            hash: self.hash()?,
            server_id: self.server_id.clone(),
            params: *params,
            rho_table: None,
        })
    }
}

/// Setup that passed FR-S7.
pub struct VerifiedSetup {
    pk: PaillierPk,
    df: DfParams,
    h: ProjectivePoint,
    f: ProjectivePoint,
    hash: [u8; 32],
    server_id: Vec<u8>,
    params: Params,
    rho_table: Option<FixedBase>,
}

impl VerifiedSetup {
    /// Identifier of the server this setup belongs to (part of every ssid).
    pub fn server_id(&self) -> &[u8] {
        &self.server_id
    }

    pub fn paillier_pk(&self) -> &PaillierPk {
        &self.pk
    }
    pub fn df(&self) -> &DfParams {
        &self.df
    }
    pub fn h(&self) -> &ProjectivePoint {
        &self.h
    }
    pub fn f(&self) -> &ProjectivePoint {
        &self.f
    }
    /// `sid = SHA-256(SetupData)`; the value pinned by the application (FR-S8).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
    pub fn params(&self) -> &Params {
        &self.params
    }
    pub fn rho_table(&self) -> Option<&FixedBase> {
        self.rho_table.as_ref()
    }

    /// Fixed-base tables: `ρ` for exponents below `2^{n_λ0}` with `rho_window`, and
    /// `t, s₁, s₂` for exponents below `2^{df_bits}` with `df_window`.
    pub fn with_tables_custom(mut self, rho_window: u32, df_bits: u32, df_window: u32) -> Self {
        let rho = self.pk.rho().clone();
        self.rho_table = Some(FixedBase::new(
            self.pk.mod_n2(),
            &rho,
            self.params.n_lambda0(),
            rho_window,
        ));
        self.df = self.df.with_tables(df_bits, df_window);
        self
    }

    /// Default tables sized for the exponents of Π_sig and signing (mask widths include ε):
    /// `ρ`: `n_λ0 + ε` bits (window 4), `t`: `n_tρ + ε`, `s₁`: `n_a + ε`, `s₂`: `n_b + ε` (window 3).
    pub fn with_tables(mut self) -> Self {
        let p = self.params;
        let eps = p.eps();
        self.rho_table = Some(FixedBase::new(
            self.pk.mod_n2(),
            self.pk.rho(),
            p.n_lambda0() + eps,
            RHO_TABLE_WINDOW,
        ));
        self.df = self.df.with_tables_sized(
            [p.n_t_rho + eps, p.n_a() + eps, p.n_b() + eps],
            DF_TABLE_WINDOW,
        );
        self
    }

    /// Total memory of the tables in bytes.
    pub fn tables_size_bytes(&self) -> usize {
        self.rho_table.as_ref().map_or(0, FixedBase::size_bytes) + self.df.tables_size_bytes()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{
        params::{PARAMS_128, ParamsId},
        rsa::tough::{ToughSpec, sample_tough_prime},
        zk::{fac::FacParams, modulus::ModRep},
    };
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use std::{sync::OnceLock, time::Instant};

    fn small_params() -> Params {
        Params {
            id: ParamsId::P128,
            ell: 16,
            nu: 16,
            n_rsa: 512,
            r_mod: 8,
            r_df: 16,
            r_df_star: 4,
            tough_count: 4,
            tough_bits: 64,
            ..PARAMS_128
        }
    }

    struct Fx {
        fac: FacParams,
        data: SetupData,
        other: SetupData,
        sk: ServerSetupSecret,
    }

    fn fx() -> &'static Fx {
        static F: OnceLock<Fx> = OnceLock::new();
        F.get_or_init(|| {
            let p = small_params();
            let mut rng = ChaCha8Rng::seed_from_u64(1);
            let d_bits = p.n_rsa + 2 * p.ell + 2 * p.nu + 4;
            let d = sample_tough_prime(&mut rng, d_bits, 7, ToughSpec::SAFE).unwrap();
            let fac = FacParams::new(d.p().clone()).unwrap();
            let (data, sk) = server_setup_with(&mut rng, &p, &fac, [7u8; 32], b"server-A").unwrap();
            let (other, _) = server_setup_with(&mut rng, &p, &fac, [9u8; 32], b"server-B").unwrap();
            Fx {
                fac,
                data,
                other,
                sk,
            }
        })
    }

    fn ok(d: &SetupData) -> bool {
        d.verify_with(&small_params(), &fx().fac).is_ok()
    }

    #[test]
    fn server_secret_export_roundtrip_and_binding() {
        let f = fx();
        let p = small_params();
        let bytes = f.sk.export_secret(&p).unwrap();
        let back = ServerSetupSecret::import_secret(&bytes, &f.data).unwrap();
        let pk = f.data.paillier_pk().unwrap();
        let c = pk.g_pow(&SBig::from_i64(777));
        let m = back.paillier_sk().dec(&c).unwrap();
        assert_eq!(resized(&m, 64), BoxedUint::from(777u64));
        // a secret does not fit another setup
        assert!(ServerSetupSecret::import_secret(&bytes, &f.other).is_err());
        // malformed encodings
        assert!(ServerSetupSecret::import_secret(&bytes[1..], &f.data).is_err());
        let mut bad = bytes.to_vec();
        bad[0] ^= 1;
        assert!(ServerSetupSecret::import_secret(&bad, &f.data).is_err());
        let mut bad = bytes.to_vec();
        *bad.last_mut().unwrap() ^= 2;
        assert!(ServerSetupSecret::import_secret(&bad, &f.data).is_err());
    }

    #[test]
    fn honest_setup_verifies() {
        let f = fx();
        let v = f.data.verify_with(&small_params(), &f.fac).unwrap();
        assert_eq!(v.hash(), f.data.hash().unwrap());
        assert_eq!(v.paillier_pk().n(), &f.data.n);
        assert_eq!(
            f.data.verify_with(&small_params(), &f.fac).unwrap().hash(),
            v.hash()
        );
        assert_eq!(std::format!("{:?}", f.sk), "ServerSetupSecret(***)");
        // decryption works with the secret key
        let pk = f.data.paillier_pk().unwrap();
        let c = pk.g_pow(&SBig::from_i64(12345));
        let m = f.sk.paillier_sk().dec(&c).unwrap();
        assert_eq!(resized(&m, 64), BoxedUint::from(12345u64));
        let v = v.with_tables();
        assert!(v.rho_table().is_some() && v.tables_size_bytes() > 0);
        // wrong params rejected
        let mut p2 = small_params();
        p2.r_mod = 9;
        assert!(f.data.verify_with(&p2, &f.fac).is_err());
    }

    #[test]
    fn roundtrip_and_strict_length() {
        let f = fx();
        let p = small_params();
        let bytes = f.data.to_bytes().unwrap();
        let back = SetupData::from_bytes_with(&bytes, &p, &f.fac).unwrap();
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert!(ok(&back));
        assert!(SetupData::from_bytes_with(&bytes[1..], &p, &f.fac).is_err());
        assert!(SetupData::from_bytes_with(&bytes[..bytes.len() - 1], &p, &f.fac).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(SetupData::from_bytes_with(&long, &p, &f.fac).is_err());
        assert!(SetupData::from_bytes_with(&[], &p, &f.fac).is_err());
    }

    #[test]
    fn byte_flip_in_every_field_rejected() {
        let f = fx();
        let p = small_params();
        let bytes = f.data.to_bytes().unwrap();
        let len = nb(&p);
        let sl = f.data.server_id.len();
        let mut regions: Vec<(usize, usize)> = std::vec![(0, 1), (1, 32), (33, 2), (35, sl)];
        let mut pos = 35 + sl;
        for l in [len, len, len, 2 * len, len, len, len, 33, 33] {
            regions.push((pos, l));
            pos += l;
        }
        for l in [
            ModProof::encoded_len(&p, p.n_rsa),
            FacProof::encoded_len(&p, &f.fac, p.n_rsa),
            DfProof::encoded_len(&p),
        ] {
            regions.push((pos, l));
            pos += l;
        }
        assert_eq!(pos, bytes.len());
        let orig = f.data.hash().unwrap();
        for (start, l) in regions {
            for off in [0, l / 2, l - 1] {
                for bit in [0x01u8, 0x80] {
                    let mut b = bytes.clone();
                    b[start + off] ^= bit;
                    match SetupData::from_bytes_with(&b, &p, &f.fac) {
                        Err(_) => {}
                        Ok(d) => {
                            assert!(!ok(&d), "flip at {} accepted", start + off);
                            assert_ne!(d.hash().unwrap(), orig);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn field_tampering_rejected() {
        let f = fx();
        let one = |b: &BoxedUint| {
            let bits = b.bits_precision();
            b.wrapping_add(BoxedUint::one_with_precision(bits))
        };
        let orig = f.data.hash().unwrap();
        let mut cases: Vec<SetupData> = Vec::new();
        let mut d = f.data.clone();
        core::mem::swap(&mut d.h, &mut d.f);
        cases.push(d);
        let mut d = f.data.clone();
        d.h += d.f;
        cases.push(d);
        let mut d = f.data.clone();
        d.rho = one(&d.rho);
        cases.push(d);
        let mut d = f.data.clone();
        d.rho0 = one(&d.rho0);
        cases.push(d);
        let mut d = f.data.clone();
        d.t = one(&d.t);
        cases.push(d);
        let mut d = f.data.clone();
        d.s1 = d.s2.clone();
        cases.push(d);
        let mut d = f.data.clone();
        d.s2 = BoxedUint::zero_with_precision(512);
        cases.push(d);
        // N̂ of the wrong size / N swapped for N̂ / other server's moduli
        let mut d = f.data.clone();
        d.n_hat = d.n_hat.shr_vartime(1).unwrap();
        cases.push(d);
        let mut d = f.data.clone();
        d.n = d.n_hat.clone();
        cases.push(d);
        let mut d = f.data.clone();
        d.n = f.other.n.clone();
        cases.push(d);
        // proofs / ids from another setup
        let mut d = f.data.clone();
        d.pi_mod = f.other.pi_mod.clone();
        cases.push(d);
        let mut d = f.data.clone();
        d.pi_fac = f.other.pi_fac.clone();
        cases.push(d);
        let mut d = f.data.clone();
        d.pi_df = f.other.pi_df.clone();
        cases.push(d);
        let mut d = f.data.clone();
        d.server_id = f.other.server_id.clone();
        cases.push(d);
        let mut d = f.data.clone();
        d.setup_id = f.other.setup_id;
        cases.push(d);
        let mut d = f.data.clone();
        d.server_id = std::vec![0u8; 257];
        cases.push(d);
        // proof field edits
        let mut d = f.data.clone();
        d.pi_mod.reps[0] = ModRep {
            a: !d.pi_mod.reps[0].a,
            ..d.pi_mod.reps[0].clone()
        };
        cases.push(d);
        let mut d = f.data.clone();
        d.pi_df.e[0] ^= 1;
        cases.push(d);
        let mut d = f.data.clone();
        d.pi_fac.w = one(&d.pi_fac.w);
        cases.push(d);
        for (i, d) in cases.iter().enumerate() {
            assert!(!ok(d), "case {i} accepted");
            if let Ok(h) = d.hash() {
                assert_ne!(h, orig, "case {i}");
            }
        }
        assert!(ok(&f.data));
    }

    #[test]
    fn server_id_limit() {
        let p = small_params();
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let r = server_setup_with(&mut rng, &p, &fx().fac, [0; 32], &[0u8; 257]);
        assert!(r.is_err());
    }

    #[test]
    #[ignore]
    fn full_size_setup() {
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        let t0 = Instant::now();
        let (data, _sk) = server_setup(&mut rng, &PARAMS_128, [1u8; 32], b"example.org").unwrap();
        std::println!("server setup: {:?}", t0.elapsed());
        let bytes = data.to_bytes().unwrap();
        std::println!("setup size: {} bytes", bytes.len());
        let data = SetupData::from_bytes(&bytes, &PARAMS_128).unwrap();
        let fac = FacParams::standard().unwrap();
        let t0 = Instant::now();
        data.check_basic().unwrap();
        std::println!("check_basic: {:?}", t0.elapsed());
        let t0 = Instant::now();
        let want = rho_of(&data.n, &data.rho0).unwrap();
        std::println!("rho check: {:?} {}", t0.elapsed(), want.bits());
        let tx = base_tx(&PARAMS_128, &data.setup_id, &data.server_id);
        let t0 = Instant::now();
        data.pi_fac.verify(&tx, &PARAMS_128, &fac, &data.n).unwrap();
        std::println!("fac verify: {:?}", t0.elapsed());
        let st = DfStatement::from_uints(&data.n_hat, &data.t, &data.s1, &data.s2).unwrap();
        let t0 = Instant::now();
        data.pi_df.verify(&tx, &PARAMS_128, &st).unwrap();
        std::println!("df verify: {:?}", t0.elapsed());
        let t0 = Instant::now();
        data.pi_mod
            .verify(&tx, &PARAMS_128, &data.n, PARAMS_128.n_rsa)
            .unwrap();
        std::println!("mod verify: {:?}", t0.elapsed());
        let t0 = Instant::now();
        let v = data.verify(&PARAMS_128).unwrap();
        std::println!("client verify total: {:?}", t0.elapsed());
        let t0 = Instant::now();
        let v = v.with_tables();
        std::println!(
            "tables: {:?}, {} bytes (rho {}, df {})",
            t0.elapsed(),
            v.tables_size_bytes(),
            v.rho_table().map_or(0, FixedBase::size_bytes),
            v.df().tables_size_bytes()
        );
        assert_eq!(v.hash(), data.hash().unwrap());
    }
}
