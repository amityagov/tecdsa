//! Server side of Protocol 2.
use alloc::vec::Vec;
use k256::ProjectivePoint;
use rand_core::CryptoRng;
use zeroize::ZeroizeOnDrop;

use super::{ServerKeyShare, commitment, decode_client_tuple, tx_base};
use crate::{
    arith::sbig::{SBig, SRange},
    curve::{decode_point, encode_point, sbig_to_scalar},
    error::Result,
    messages::{KgMsg1, KgMsg2, KgMsg3},
    paillier::PaillierPk,
    params::Params,
    setup::SetupData,
    ssid::Ssid,
    transcript::uint_to_be,
    zk::{
        df_star::DfStarProof,
        dlenc::{DlencProof, DlencStatement, DlencWitness},
        dlog::DlogProof,
    },
};

/// Entry point: step 1 of the server.
pub struct ServerKeygen0;

impl ServerKeygen0 {
    /// Samples `x₂′ ← ±2^{n_x}`, returns the state and `KgMsg1` (envelope bytes).
    pub fn start<R: CryptoRng + ?Sized>(
        rng: &mut R,
        params: &Params,
        setup: &SetupData,
        client_id: &[u8],
    ) -> Result<(ServerKeygen1, Vec<u8>)> {
        let pk = setup.paillier_pk()?;
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let ssid = Ssid::keygen(setup.hash()?, &setup.server_id, client_id, &nonce)?;
        let x2p = SBig::random_in(rng, SRange::pm_pow2(params.n_x()));
        let x2_pub = ProjectivePoint::GENERATOR * sbig_to_scalar(&x2p)?;
        let b = commitment(params, &ssid, &x2_pub);
        let msg = KgMsg1 {
            kg_nonce: nonce.to_vec(),
            b: b.to_vec(),
        }
        .encode(params)?;
        Ok((
            ServerKeygen1 {
                params: *params,
                ssid,
                pk,
                x2p,
                x2_pub,
            },
            msg,
        ))
    }
}

/// State after `KgMsg1` was sent; consumed by [`ServerKeygen1::on_msg2`].
#[derive(ZeroizeOnDrop)]
pub struct ServerKeygen1 {
    #[zeroize(skip)]
    params: Params,
    #[zeroize(skip)]
    ssid: Ssid,
    #[zeroize(skip)]
    pk: PaillierPk,
    x2p: SBig,
    #[zeroize(skip)]
    x2_pub: ProjectivePoint,
}

impl ServerKeygen1 {
    /// Steps 2–3: verifies `ψ_df*` and `ψ_dlog`, produces `KgMsg3` and the server's key share.
    pub fn on_msg2<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        msg2: &[u8],
    ) -> Result<(ServerKeyShare, Vec<u8>)> {
        let params = &self.params;
        let m = KgMsg2::decode(msg2, params)?;
        let x1_pub = decode_point(&m.x1)?;
        let client = decode_client_tuple(params, &m.m_hat, &m.v, &m.u1, &m.u2)?;
        let psi_df = DfStarProof::decode(&m.psi_df_star, params)?;
        let psi_dlog = DlogProof::decode(&m.psi_dlog, params)?;

        let tx_c = tx_base(params, &self.ssid, "C");
        psi_df.verify(&tx_c, params, &client)?;
        psi_dlog.verify(&tx_c, params, &x1_pub)?;

        let beta = SBig::random_in(rng, SRange::pm_pow2(params.n_lambda()));
        let e_ct = self.pk.enc(&self.x2p, &beta, params.n_lambda())?;
        let tx_s = tx_base(params, &self.ssid, "S");
        let stmt = DlencStatement {
            x_pub: &self.x2_pub,
            e_ct: &e_ct,
            pk: &self.pk,
            client: &client,
        };
        let psi = DlencProof::prove(
            rng,
            &tx_s,
            params,
            &stmt,
            &DlencWitness::new(self.x2p.clone(), beta),
        )?;

        let e_len = (2 * params.n_rsa as usize).div_ceil(8);
        let e_bytes = uint_to_be(&e_ct.retrieve(), e_len)?;
        let msg3 = KgMsg3 {
            x2: encode_point(&self.x2_pub).to_vec(),
            e: e_bytes.clone(),
            psi_dlenc: psi.encode(params)?,
        }
        .encode(params)?;
        let share = ServerKeyShare::new(sbig_to_scalar(&self.x2p)?, x1_pub + self.x2_pub, e_bytes);
        Ok((share, msg3))
    }
}

#[cfg(test)]
impl ServerKeygen1 {
    pub(crate) fn test_clone(&self) -> Self {
        Self {
            params: self.params,
            ssid: self.ssid.clone(),
            pk: self.pk.clone(),
            x2p: self.x2p.clone(),
            x2_pub: self.x2_pub,
        }
    }
}
