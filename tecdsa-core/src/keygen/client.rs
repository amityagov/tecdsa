//! Client side of Protocol 2.
use alloc::vec::Vec;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use super::{
    ClientKeyShare, Clock, KEYGEN_TIMEOUT_MS, canonical_uint, commitment, encode_client_tuple,
    tx_base,
};
use crate::{
    curve::{decode_point, encode_point, random_nonzero_scalar},
    error::{Error, Result},
    messages::{KgMsg1, KgMsg2, KgMsg3},
    paillier::PaillierPk,
    params::Params,
    rsa::tough::sample_df_client,
    setup::VerifiedSetup,
    ssid::Ssid,
    zk::{
        df::{DfStatement, DfWitness},
        df_star::DfStarProof,
        dlenc::{DlencProof, DlencStatement},
        dlog::DlogProof,
    },
};

/// Entry point: step 2 of the client (reacts to `KgMsg1`).
pub struct ClientKeygen0;

impl ClientKeygen0 {
    /// Samples `x₁` and the ephemeral DF tuple, proves them and returns `KgMsg2`.
    /// The 60-second timer starts when this returns.
    pub fn on_msg1<R: CryptoRng + ?Sized, C: Clock>(
        rng: &mut R,
        clock: &C,
        setup: &VerifiedSetup,
        client_id: &[u8],
        msg1: &[u8],
    ) -> Result<(ClientKeygen1, Vec<u8>)> {
        let params = *setup.params();
        let m1 = KgMsg1::decode(msg1, &params)?;
        let nonce: [u8; 32] = m1
            .kg_nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?;
        let b: [u8; 32] =
            m1.b.as_slice()
                .try_into()
                .map_err(|_| Error::InvalidEncoding)?;
        let ssid = Ssid::keygen(setup.hash(), setup.server_id(), client_id, &nonce)?;

        let x1 = random_nonzero_scalar(rng);
        let x1_pub = ProjectivePoint::GENERATOR * x1;
        let tuple = sample_df_client(rng, &params)?;
        let client = DfStatement::client(&tuple.n_hat, &tuple.t, &tuple.s1, &tuple.s2)?;
        let tx_c = tx_base(&params, &ssid, "C");
        let psi_df = DfStarProof::prove(
            rng,
            &tx_c,
            &params,
            &client,
            &DfWitness::from_secret(&tuple.secret),
        )?;
        // The factorization of M̂ is never needed again: destroy it right away.
        drop(tuple);
        let psi_dlog = DlogProof::prove(rng, &tx_c, &params, &x1_pub, &x1)?;

        let [m_hat, v, u1, u2] = encode_client_tuple(&params, &client)?;
        let msg2 = KgMsg2 {
            x1: encode_point(&x1_pub).to_vec(),
            m_hat,
            v,
            u1,
            u2,
            psi_df_star: psi_df.encode(&params)?,
            psi_dlog: psi_dlog.encode(&params)?,
        }
        .encode(&params)?;
        let state = ClientKeygen1 {
            params,
            ssid,
            pk: setup.paillier_pk().clone(),
            b,
            x1,
            x1_pub,
            client,
            sent_at_ms: clock.now_ms(),
        };
        Ok((state, msg2))
    }
}

/// State after `KgMsg2` was sent; consumed by [`ClientKeygen1::on_msg3`].
#[derive(ZeroizeOnDrop)]
pub struct ClientKeygen1 {
    #[zeroize(skip)]
    params: Params,
    #[zeroize(skip)]
    ssid: Ssid,
    #[zeroize(skip)]
    pk: PaillierPk,
    #[zeroize(skip)]
    b: [u8; 32],
    x1: Scalar,
    #[zeroize(skip)]
    x1_pub: ProjectivePoint,
    #[zeroize(skip)]
    client: DfStatement,
    #[zeroize(skip)]
    sent_at_ms: u64,
}

impl ClientKeygen1 {
    /// Step 4: timer, `E ∈ Z*_{N²}`, `B = RO(ssid, S, X₂)`, `ψ_dlenc`.
    pub fn on_msg3<C: Clock>(self, clock: &C, msg3: &[u8]) -> Result<ClientKeyShare> {
        let params = &self.params;
        if clock.now_ms().saturating_sub(self.sent_at_ms) > KEYGEN_TIMEOUT_MS {
            return Err(Error::Timeout);
        }
        let m = KgMsg3::decode(msg3, params)?;
        let x2_pub = decode_point(&m.x2)?;
        if !bool::from(commitment(params, &self.ssid, &x2_pub).ct_eq(&self.b)) {
            return Err(Error::VerificationFailed);
        }
        let e_len = (2 * params.n_rsa as usize).div_ceil(8);
        let e_int = canonical_uint(&m.e, e_len, self.pk.mod_n2().modulus().as_ref())?;
        let e_ct = self.pk.check_ciphertext(&e_int)?;
        let psi = DlencProof::decode(&m.psi_dlenc, params)?;
        let tx_s = tx_base(params, &self.ssid, "S");
        let stmt = DlencStatement {
            x_pub: &x2_pub,
            e_ct: &e_ct,
            pk: &self.pk,
            client: &self.client,
        };
        psi.verify(&tx_s, params, &stmt)?;
        Ok(ClientKeyShare::new(self.x1, self.x1_pub + x2_pub, m.e))
    }
}

#[cfg(test)]
impl ClientKeygen1 {
    pub(crate) fn test_clone(&self) -> Self {
        Self {
            params: self.params,
            ssid: self.ssid.clone(),
            pk: self.pk.clone(),
            b: self.b,
            x1: self.x1,
            x1_pub: self.x1_pub,
            client: self.client.clone(),
            sent_at_ms: self.sent_at_ms,
        }
    }
}
