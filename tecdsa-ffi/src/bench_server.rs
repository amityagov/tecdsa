//! In-process server for benchmarks on a device without a network (feature `bench-server`).
//! One keygen and one signing session at a time; not meant for production use.
use std::sync::{Arc, Mutex};

use getrandom::{
    SysRng,
    rand_core::{Rng, UnwrapErr},
};
use tecdsa_core::{
    keygen::{ServerKeyShare, ServerKeygen0, ServerKeygen1},
    params::Params,
    setup::{ServerSetupSecret, SetupData, VerifiedSetup, server_setup},
    sign::{ServerSign0, ServerSign1},
};

use crate::{Profile, TecdsaError, params};

#[derive(Default)]
struct Sessions {
    keygen: Option<ServerKeygen1>,
    share: Option<ServerKeyShare>,
    sign: Option<ServerSign1>,
    client_id: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct BenchServer {
    params: Params,
    data: SetupData,
    secret: ServerSetupSecret,
    view: VerifiedSetup,
    sessions: Mutex<Sessions>,
}

fn lock(m: &Mutex<Sessions>) -> Result<std::sync::MutexGuard<'_, Sessions>, TecdsaError> {
    m.lock().map_err(|_| TecdsaError::Internal)
}

#[uniffi::export]
impl BenchServer {
    /// Runs the server setup (SampleRSA, SampleDF and proofs): the slow part, ≈1 s on a laptop.
    #[uniffi::constructor]
    pub fn new(profile: Profile, server_id: Vec<u8>) -> Result<Arc<Self>, TecdsaError> {
        let params = params(profile);
        let mut rng = UnwrapErr(SysRng);
        let mut setup_id = [0u8; 32];
        rng.fill_bytes(&mut setup_id);
        let (data, secret) = server_setup(&mut rng, &params, setup_id, &server_id)?;
        let view = data.assume_verified(&params)?.with_tables();
        Ok(Arc::new(Self {
            params,
            data,
            secret,
            view,
            sessions: Mutex::default(),
        }))
    }

    pub fn setup_bytes(&self) -> Result<Vec<u8>, TecdsaError> {
        Ok(self.data.to_bytes()?)
    }

    pub fn keygen_msg1(&self, client_id: Vec<u8>) -> Result<Vec<u8>, TecdsaError> {
        let (st, m1) =
            ServerKeygen0::start(&mut UnwrapErr(SysRng), &self.params, &self.data, &client_id)?;
        let mut s = lock(&self.sessions)?;
        s.keygen = Some(st);
        s.client_id = client_id;
        Ok(m1)
    }

    pub fn keygen_msg3(&self, msg2: Vec<u8>) -> Result<Vec<u8>, TecdsaError> {
        let mut s = lock(&self.sessions)?;
        let st = s.keygen.take().ok_or(TecdsaError::SessionConsumed)?;
        let (share, m3) = st.on_msg2(&mut UnwrapErr(SysRng), &msg2)?;
        s.share = Some(share);
        Ok(m3)
    }

    pub fn sign_msg1(
        &self,
        digest: Vec<u8>,
        hd: Option<crate::HdPathArg>,
    ) -> Result<Vec<u8>, TecdsaError> {
        let hd = crate::hd_from(hd)?;
        let d: [u8; 32] = digest.try_into().map_err(|_| TecdsaError::InvalidInput)?;
        let mut s = lock(&self.sessions)?;
        let share = s.share.as_ref().ok_or(TecdsaError::NotFound)?;
        let (st, m1) = ServerSign0::start(
            &mut UnwrapErr(SysRng),
            &self.view,
            share,
            &s.client_id,
            &d,
            hd.as_ref(),
        )?;
        s.sign = Some(st);
        Ok(m1)
    }

    /// Returns `SignMsg3` (r, s, recid).
    pub fn sign_finish(&self, msg2: Vec<u8>) -> Result<Vec<u8>, TecdsaError> {
        let st = lock(&self.sessions)?
            .sign
            .take()
            .ok_or(TecdsaError::SessionConsumed)?;
        let (_, m3) = st.finish(&self.view, self.secret.paillier_sk(), &msg2)?;
        Ok(m3)
    }
}
