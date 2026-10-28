//! Client side of Protocol 3.
use alloc::vec::Vec;
use crypto_bigint::{BoxedUint, NonZero};
use k256::{ProjectivePoint, Scalar, ecdsa::VerifyingKey};
use rand_core::CryptoRng;

use super::{
    Signature, decode_signature, digest_scalar, ecdsa_verify, hedged_nonce, nonce_challenge,
    tx_base,
};
use crate::{
    arith::{
        monty::Residue,
        sbig::{SBig, SRange, resized},
    },
    curve::{decode_point, encode_point, encode_scalar, order, x_coord},
    error::{Error, Result},
    keygen::{ClientKeyShare, canonical_uint},
    messages::{SignMsg1, SignMsg2, SignMsg3},
    params::Params,
    setup::VerifiedSetup,
    ssid::Ssid,
    transcript::{uint_from_be, uint_to_be},
    zk::sig::{SigProof, SigStatement, SigWitness},
};

const MAX_RESAMPLE: usize = 64;

/// Client side of signing (a single step: `SignMsg1` in, `SignMsg2` out).
pub struct ClientSign;

fn scalar_to_sbig(s: &Scalar) -> Result<SBig> {
    Ok(SBig::from_uint(uint_from_be(&encode_scalar(s), 256)?))
}

/// `⌊2^bits / q⌋` as the size of the interval the masking multiplier is drawn from.
fn mask_interval(bits: u32) -> Result<BoxedUint> {
    let q = order();
    let prec = bits.max(q.bits_precision()) + 64;
    let num = BoxedUint::one_with_precision(prec).shl(bits);
    let qnz = Option::<NonZero<BoxedUint>>::from(resized(&q, prec).to_nz())
        .ok_or(Error::InvalidModulus)?;
    Ok(num.div_rem_vartime(&qnz).0)
}

impl ClientSign {
    /// Verifies `SignMsg1`, computes `S` and `ψ_sig`, returns `SignMsg2` (envelope bytes).
    /// `setup` should have its fixed-base tables built (`with_tables`) to meet the time budget.
    pub fn respond<R: CryptoRng + ?Sized>(
        rng: &mut R,
        setup: &VerifiedSetup,
        share: &ClientKeyShare,
        client_id: &[u8],
        digest: &[u8; 32],
        msg1: &[u8],
    ) -> Result<Vec<u8>> {
        let params = setup.params();
        super::check_digest(digest)?;
        let m1 = SignMsg1::decode(msg1, params)?;
        let r2 = decode_point(&m1.r2)?;
        let y = decode_point(&m1.y)?;
        let x1 = *share.secret();
        if r2 * x1 != y {
            return Err(Error::VerificationFailed);
        }
        let x_pub = *share.public_key();
        let ssid = Ssid::sign(
            setup.hash(),
            setup.server_id(),
            client_id,
            &share.key_id(),
            digest,
            &encode_point(&r2),
        )?;

        let mut ctx = Vec::with_capacity(96);
        ctx.extend_from_slice(&ssid.encode());
        let k1 = hedged_nonce(rng, "k1", &x1, &ctx);
        let r1 = ProjectivePoint::GENERATOR * k1;
        let r_pt = r2 * k1;
        let e = nonce_challenge(params, &ssid, &x_pub, &r1, &r_pt, digest);
        let r = x_coord(&((r2 + ProjectivePoint::GENERATOR * e) * k1));
        let m = digest_scalar(digest);
        let k1_inv = Option::<Scalar>::from(k256::elliptic_curve::Field::invert(&k1))
            .ok_or(Error::VerificationFailed)?;
        let t1 = scalar_to_sbig(&(k1_inv * (m + r * x1)))?;
        let t2 = scalar_to_sbig(&(k1_inv * r))?;
        let q = SBig::from_uint(order());

        // u = [k₁⁻¹(m + r·x₁)]_q + µ·q, v = [k₁⁻¹·r]_q + µ′·q (resample on the negligible overflow).
        let (size_a, size_b) = (mask_interval(params.n_a())?, mask_interval(params.n_b())?);
        let (a_range, b_range) = (SRange::pm_pow2(params.n_a()), SRange::pm_pow2(params.n_b()));
        let (mut u, mut v) = (SBig::zero(64), SBig::zero(64));
        for i in 0..MAX_RESAMPLE {
            u = t1.add(&SBig::random_in_size(rng, &size_a)?.mul(&q));
            v = t2.add(&SBig::random_in_size(rng, &size_b)?.mul(&q));
            if u.in_range(a_range) && v.in_range(b_range) {
                break;
            }
            if i + 1 == MAX_RESAMPLE {
                return Err(Error::OutOfRange);
            }
        }
        let lambda0 = SBig::random_in(rng, SRange::pm_pow2(params.n_lambda0()));

        // S = enc_N(u; ρ^{λ₀}) · E^v mod N²
        let pk = setup.paillier_pk();
        let s_len = (2 * params.n_rsa as usize).div_ceil(8);
        let e_int = canonical_uint(share.e_bytes(), s_len, pk.mod_n2().modulus().as_ref())?;
        let e_ct = pk.check_ciphertext(&e_int)?;
        let rho_pow: Residue = match setup.rho_table() {
            Some(t) if t.max_bits() >= params.n_lambda0() => t.pow_ct(&lambda0)?,
            _ => pk.mod_n2().pow_ct(pk.rho(), &lambda0, params.n_lambda0())?,
        };
        let s_ct = pk
            .g_pow(&u)
            .mul(&rho_pow)
            .mul(&pk.scale(&e_ct, &v, params.n_b())?);

        let stmt = SigStatement {
            h: setup.h(),
            f: setup.f(),
            pk,
            df: setup.df(),
            e_ct: &e_ct,
            s_ct: &s_ct,
            rho_table: setup.rho_table(),
        };
        let psi = SigProof::prove(
            rng,
            &tx_base(params, &ssid, "C"),
            params,
            &stmt,
            &SigWitness {
                a: u,
                b: v,
                lambda0,
            },
        )?;
        SignMsg2 {
            r1: encode_point(&r1).to_vec(),
            r: encode_point(&r_pt).to_vec(),
            s_ct: uint_to_be(&s_ct.retrieve(), s_len)?,
            psi_sig: psi.encode(params)?,
        }
        .encode(params)
    }

    /// Optional `SignMsg3`: checks the server's result locally against `X` and the digest.
    pub fn verify_final(
        params: &Params,
        share: &ClientKeyShare,
        digest: &[u8; 32],
        msg3: &[u8],
    ) -> Result<Signature> {
        let m = SignMsg3::decode(msg3, params)?;
        let sig = decode_signature(&m.r, &m.s, m.recid)?;
        ecdsa_verify(share.public_key(), digest, &sig)?;
        // The recovery id must point back to the same key.
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(
            digest,
            &sig.to_ecdsa()?,
            sig.recovery_id()?,
        )
        .map_err(|_| Error::VerificationFailed)?;
        if VerifyingKey::from_affine(share.public_key().to_affine()).ok() != Some(vk) {
            return Err(Error::VerificationFailed);
        }
        Ok(sig)
    }
}
