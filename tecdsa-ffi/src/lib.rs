//! Swift (and other) bindings for the client side of `tecdsa-core` via UniFFI.
//!
//! The client share never crosses the FFI boundary: it is written to and read from the
//! application's [`SecretStore`] (Keychain on iOS) inside this crate.
#![forbid(unsafe_code)]

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use getrandom::{SysRng, rand_core::UnwrapErr};
use tecdsa_core::{
    error::Error as CoreError,
    keygen::{ClientKeyShare, ClientKeygen0, Clock},
    params::{PARAMS_112, PARAMS_128, Params},
    setup::{SetupData, VerifiedSetup},
    sign::ClientSign,
    store::SecretStore as CoreStore,
};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TecdsaError {
    #[error("verification failed")]
    Verification,
    #[error("session timed out")]
    Timeout,
    #[error("invalid input")]
    InvalidInput,
    #[error("secret not found")]
    NotFound,
    #[error("secret store failure")]
    Storage,
    #[error("session already used")]
    SessionConsumed,
    #[error("internal error")]
    Internal,
}

impl From<CoreError> for TecdsaError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::VerificationFailed => Self::Verification,
            CoreError::Timeout => Self::Timeout,
            CoreError::NotFound => Self::NotFound,
            CoreError::Storage => Self::Storage,
            CoreError::InvalidEncoding | CoreError::OutOfRange | CoreError::InvalidModulus => {
                Self::InvalidInput
            }
            _ => Self::Internal,
        }
    }
}

#[derive(Clone, Copy, uniffi::Enum)]
pub enum Profile {
    /// 128-bit security.
    P128,
    /// 112-bit security.
    P112,
}

fn params(p: Profile) -> Params {
    match p {
        Profile::P128 => PARAMS_128,
        Profile::P112 => PARAMS_112,
    }
}

/// Application-provided secret storage (iOS Keychain, Android Keystore, ...).
#[uniffi::export(with_foreign)]
pub trait SecretStore: Send + Sync {
    fn put(&self, key: String, value: Vec<u8>) -> Result<(), TecdsaError>;
    fn get(&self, key: String) -> Result<Option<Vec<u8>>, TecdsaError>;
    fn delete(&self, key: String) -> Result<(), TecdsaError>;
}

struct StoreAdapter(Arc<dyn SecretStore>);

impl CoreStore for StoreAdapter {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), CoreError> {
        self.0
            .put(key.into(), value.to_vec())
            .map_err(|_| CoreError::Storage)
    }
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, CoreError> {
        self.0
            .get(key.into())
            .map(|o| o.map(Zeroizing::new))
            .map_err(|_| CoreError::Storage)
    }
    fn delete(&self, key: &str) -> Result<(), CoreError> {
        self.0.delete(key.into()).map_err(|_| CoreError::Storage)
    }
}

struct MonotonicClock(Instant);

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn digest32(d: &[u8]) -> Result<[u8; 32], TecdsaError> {
    d.try_into().map_err(|_| TecdsaError::InvalidInput)
}

/// The server's setup after the (expensive, ≈1–4 s on a phone) proof verification, with
/// precomputed tables (≈7 MiB). Create once per server and reuse for all sessions.
#[derive(uniffi::Object)]
pub struct ClientSetup {
    inner: VerifiedSetup,
    profile: Profile,
}

#[uniffi::export]
impl ClientSetup {
    /// Verifies `SetupData` received from the server (FR-S7). Run off the main thread.
    #[uniffi::constructor]
    pub fn verify(setup_bytes: Vec<u8>, profile: Profile) -> Result<Arc<Self>, TecdsaError> {
        let p = params(profile);
        let data = SetupData::from_bytes(&setup_bytes, &p)?;
        let inner = data.verify(&p)?.with_tables();
        Ok(Arc::new(Self { inner, profile }))
    }

    /// SHA-256 of the setup; pin it to detect server changes.
    pub fn hash(&self) -> Vec<u8> {
        self.inner.hash().to_vec()
    }
}

/// Result of a finished key generation.
#[derive(uniffi::Record)]
pub struct KeygenResult {
    /// Compressed SEC1 public key `X` (33 bytes).
    pub public_key: Vec<u8>,
    /// `SHA-256(X ‖ E)`.
    pub key_id: Vec<u8>,
}

/// Client side of key generation: `msg1` in, `msg2` out, then `finish(msg3)`.
#[derive(uniffi::Object)]
pub struct ClientKeygen {
    state: Mutex<Option<(ClientKeygen0Next, MonotonicClock)>>,
    msg2: Vec<u8>,
}

type ClientKeygen0Next = tecdsa_core::keygen::ClientKeygen1;

#[uniffi::export]
impl ClientKeygen {
    #[uniffi::constructor]
    pub fn start(
        setup: Arc<ClientSetup>,
        client_id: Vec<u8>,
        msg1: Vec<u8>,
    ) -> Result<Arc<Self>, TecdsaError> {
        let clock = MonotonicClock(Instant::now());
        let (next, msg2) =
            ClientKeygen0::on_msg1(&mut rng(), &clock, &setup.inner, &client_id, &msg1)?;
        Ok(Arc::new(Self {
            state: Mutex::new(Some((next, clock))),
            msg2,
        }))
    }

    /// `KgMsg2` for the server.
    pub fn msg2(&self) -> Vec<u8> {
        self.msg2.clone()
    }

    /// Processes `KgMsg3`, stores the share under `wallet_id` and returns the public data.
    /// The session can be finished only once.
    pub fn finish(
        &self,
        msg3: Vec<u8>,
        wallet_id: String,
        store: Arc<dyn SecretStore>,
    ) -> Result<KeygenResult, TecdsaError> {
        let (next, clock) = self
            .state
            .lock()
            .map_err(|_| TecdsaError::Internal)?
            .take()
            .ok_or(TecdsaError::SessionConsumed)?;
        let share = next.on_msg3(&clock, &msg3)?;
        share.save(&StoreAdapter(store), &wallet_id)?;
        Ok(KeygenResult {
            public_key: tecdsa_core::curve::encode_point(share.public_key()).to_vec(),
            key_id: share.key_id().to_vec(),
        })
    }
}

fn load_share(
    store: Arc<dyn SecretStore>,
    wallet_id: &str,
    profile: Profile,
) -> Result<ClientKeyShare, TecdsaError> {
    Ok(ClientKeyShare::load(
        &StoreAdapter(store),
        wallet_id,
        &params(profile),
    )?)
}

/// Public key (33 bytes, compressed) of a stored wallet.
#[uniffi::export]
pub fn client_public_key(
    store: Arc<dyn SecretStore>,
    wallet_id: String,
    profile: Profile,
) -> Result<Vec<u8>, TecdsaError> {
    let share = load_share(store, &wallet_id, profile)?;
    Ok(tecdsa_core::curve::encode_point(share.public_key()).to_vec())
}

/// Signing, client step: `SignMsg1` in, `SignMsg2` out. Stateless; sessions run in parallel.
#[uniffi::export]
pub fn client_sign(
    setup: Arc<ClientSetup>,
    store: Arc<dyn SecretStore>,
    wallet_id: String,
    client_id: Vec<u8>,
    digest: Vec<u8>,
    msg1: Vec<u8>,
) -> Result<Vec<u8>, TecdsaError> {
    let share = load_share(store, &wallet_id, setup.profile)?;
    Ok(ClientSign::respond(
        &mut rng(),
        &setup.inner,
        &share,
        &client_id,
        &digest32(&digest)?,
        &msg1,
    )?)
}

/// A signature accepted by the client.
#[derive(uniffi::Record)]
pub struct SignatureBytes {
    /// `r ‖ s`, 64 bytes, low-s.
    pub rs: Vec<u8>,
    pub recovery_id: u8,
}

/// Optional final step: checks the server's `SignMsg3` against the wallet's key.
#[uniffi::export]
pub fn client_verify_signature(
    store: Arc<dyn SecretStore>,
    wallet_id: String,
    profile: Profile,
    digest: Vec<u8>,
    msg3: Vec<u8>,
) -> Result<SignatureBytes, TecdsaError> {
    let share = load_share(store, &wallet_id, profile)?;
    let sig = ClientSign::verify_final(&params(profile), &share, &digest32(&digest)?, &msg3)?;
    Ok(SignatureBytes {
        rs: sig.to_bytes().to_vec(),
        recovery_id: sig.recid,
    })
}
