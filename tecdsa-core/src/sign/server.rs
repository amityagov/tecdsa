//! Server side of Protocol 3.
use alloc::vec::Vec;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRng;
use zeroize::ZeroizeOnDrop;

use super::{Signature, ecdsa_verify, finalize, hedged_nonce, nonce_challenge, tx_base};
use crate::{
    arith::sbig::{SBig, resized},
    curve::{decode_point, encode_point, encode_scalar, sbig_to_scalar, x_coord},
    error::{Error, Result},
    keygen::{ServerKeyShare, canonical_uint},
    messages::{SignMsg1, SignMsg2, SignMsg3},
    paillier::PaillierSk,
    params::Params,
    setup::VerifiedSetup,
    ssid::Ssid,
    zk::sig::{SigProof, SigStatement},
};

/// Entry point: step 1 of the server.
pub struct ServerSign0;

impl ServerSign0 {
    /// Samples `k₂`, returns the session state and `SignMsg1` (envelope bytes).
    /// Sessions are independent; `setup` is only read (FR-G5).
    pub fn start<R: CryptoRng + ?Sized>(
        rng: &mut R,
        setup: &VerifiedSetup,
        share: &ServerKeyShare,
        client_id: &[u8],
        digest: &[u8; 32],
    ) -> Result<(ServerSign1, Vec<u8>)> {
        let params = *setup.params();
        super::check_digest(digest)?;
        let x2 = *share.secret();
        let x2_pub = ProjectivePoint::GENERATOR * x2;
        let x1_pub = *share.public_key() - x2_pub;
        let key_id = share.key_id();
        let mut ctx = Vec::with_capacity(64 + client_id.len());
        ctx.extend_from_slice(&key_id);
        ctx.extend_from_slice(digest);
        ctx.extend_from_slice(client_id);
        let k2 = hedged_nonce(rng, "k2", &x2, &ctx);
        let r2 = ProjectivePoint::GENERATOR * k2;
        let y = x1_pub * k2;
        let ssid = Ssid::sign(
            setup.hash(),
            setup.server_id(),
            client_id,
            &key_id,
            digest,
            &encode_point(&r2),
        )?;
        let msg = SignMsg1 {
            r2: encode_point(&r2).to_vec(),
            y: encode_point(&y).to_vec(),
        }
        .encode(&params)?;
        Ok((
            ServerSign1 {
                params,
                ssid,
                k2,
                x_pub: *share.public_key(),
                e_bytes: share.e_bytes().to_vec(),
                digest: *digest,
            },
            msg,
        ))
    }
}

/// State after `SignMsg1`; consumed by [`ServerSign1::finish`], so `k₂` cannot be reused.
#[derive(ZeroizeOnDrop)]
pub struct ServerSign1 {
    #[zeroize(skip)]
    params: Params,
    #[zeroize(skip)]
    ssid: Ssid,
    k2: Scalar,
    #[zeroize(skip)]
    x_pub: ProjectivePoint,
    #[zeroize(skip)]
    e_bytes: Vec<u8>,
    #[zeroize(skip)]
    digest: [u8; 32],
}

impl ServerSign1 {
    /// Step 3: checks `SignMsg2`, decrypts and returns the signature plus an optional `SignMsg3`.
    pub fn finish(
        self,
        setup: &VerifiedSetup,
        sk: &PaillierSk,
        msg2: &[u8],
    ) -> Result<(Signature, Vec<u8>)> {
        let params = &self.params;
        let m = SignMsg2::decode(msg2, params)?;
        let r1 = decode_point(&m.r1)?;
        let r_pt = decode_point(&m.r)?;
        let pk = setup.paillier_pk();
        let s_len = (2 * params.n_rsa as usize).div_ceil(8);
        let s_int = canonical_uint(&m.s_ct, s_len, pk.mod_n2().modulus().as_ref())?;
        let s_ct = pk.check_ciphertext(&s_int)?;
        if r_pt != r1 * self.k2 {
            return Err(Error::VerificationFailed);
        }
        let e_int = canonical_uint(&self.e_bytes, s_len, pk.mod_n2().modulus().as_ref())?;
        let e_ct = pk.check_ciphertext(&e_int)?;
        let psi = SigProof::decode(&m.psi_sig, params)?;
        let stmt = SigStatement {
            h: setup.h(),
            f: setup.f(),
            pk,
            df: setup.df(),
            e_ct: &e_ct,
            s_ct: &s_ct,
            rho_table: setup.rho_table(),
        };
        psi.verify(&tx_base(params, &self.ssid, "C"), params, &stmt)?;

        let e = nonce_challenge(params, &self.ssid, &self.x_pub, &r1, &r_pt, &self.digest);
        let kk = self.k2 + e;
        let nonce_point = r1 * kk;
        let r = x_coord(&nonce_point);
        let kk_inv = Option::<Scalar>::from(k256::elliptic_curve::Field::invert(&kk))
            .ok_or(Error::VerificationFailed)?;

        // dec(S) = u + x₂′·v mod N, a signed integer: values above N/2 are negative.
        let dec = sk.dec(&s_ct)?;
        let n = pk.n();
        let bits = n.bits_precision().max(dec.bits_precision());
        let (dec, n_w) = (resized(&dec, bits), resized(n, bits));
        let half = n_w.shr_vartime(1).ok_or(Error::OutOfRange)?;
        let signed = if dec.cmp_vartime(&half) == core::cmp::Ordering::Greater {
            SBig::from_uint(dec).sub(&SBig::from_uint(n_w))
        } else {
            SBig::from_uint(dec)
        };
        let sigma = sbig_to_scalar(&signed)? * kk_inv;
        if bool::from(k256::elliptic_curve::Field::is_zero(&sigma))
            || bool::from(k256::elliptic_curve::Field::is_zero(&r))
        {
            return Err(Error::VerificationFailed);
        }
        let sig = finalize(&nonce_point, r, sigma);
        // The result must be an ordinary valid ECDSA signature (Protocol 3, S's output).
        ecdsa_verify(&self.x_pub, &self.digest, &sig)?;
        let msg3 = SignMsg3 {
            r: encode_scalar(&sig.r).to_vec(),
            s: encode_scalar(&sig.s).to_vec(),
            recid: sig.recid,
        }
        .encode(params)?;
        Ok((sig, msg3))
    }
}

#[cfg(test)]
impl ServerSign1 {
    pub(crate) fn test_clone(&self) -> Self {
        Self {
            params: self.params,
            ssid: self.ssid.clone(),
            k2: self.k2,
            x_pub: self.x_pub,
            e_bytes: self.e_bytes.clone(),
            digest: self.digest,
        }
    }
}
