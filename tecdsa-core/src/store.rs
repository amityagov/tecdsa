//! Persistence of secrets is the application's job (Keychain / Secure Enclave / HSM); the
//! crate only describes what it needs (spec §1, §8.4).
use alloc::{format, string::String, vec::Vec};
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    keygen::{ClientKeyShare, ServerKeyShare},
    params::Params,
};

/// Key-value store for secret blobs. Implementations must keep values confidential
/// (e.g. iOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
pub trait SecretStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn delete(&self, key: &str) -> Result<()>;
}

fn client_key(wallet_id: &str) -> String {
    format!("tecdsa/client-share/{wallet_id}")
}

fn server_key(wallet_id: &str) -> String {
    format!("tecdsa/server-share/{wallet_id}")
}

/// Writes a new secret; an existing one is never replaced (a malicious peer could otherwise
/// destroy a share by restarting key generation under a known wallet id).
fn put_new(store: &dyn SecretStore, key: &str, value: &[u8]) -> Result<()> {
    if store.get(key)?.is_some() {
        return Err(Error::AlreadyExists);
    }
    store.put(key, value)
}

impl ClientKeyShare {
    /// Writes the share through `store` (explicit `export_secret`, spec §8.2).
    /// Fails with `AlreadyExists` if the wallet already has a client share.
    pub fn save(&self, store: &dyn SecretStore, wallet_id: &str) -> Result<()> {
        put_new(store, &client_key(wallet_id), &self.export_secret())
    }

    /// Like `save`, but replaces an existing share. Only for a deliberate restore.
    pub fn replace(&self, store: &dyn SecretStore, wallet_id: &str) -> Result<()> {
        store.put(&client_key(wallet_id), &self.export_secret())
    }

    pub fn load(store: &dyn SecretStore, wallet_id: &str, params: &Params) -> Result<Self> {
        let bytes = store.get(&client_key(wallet_id))?.ok_or(Error::NotFound)?;
        Self::import_secret(&bytes, params)
    }
}

impl ServerKeyShare {
    /// Fails with `AlreadyExists` if the wallet already has a server share.
    pub fn save(&self, store: &dyn SecretStore, wallet_id: &str) -> Result<()> {
        put_new(store, &server_key(wallet_id), &self.export_secret())
    }

    /// Like `save`, but replaces an existing share. Only for a deliberate restore.
    pub fn replace(&self, store: &dyn SecretStore, wallet_id: &str) -> Result<()> {
        store.put(&server_key(wallet_id), &self.export_secret())
    }

    pub fn load(store: &dyn SecretStore, wallet_id: &str, params: &Params) -> Result<Self> {
        let bytes = store.get(&server_key(wallet_id))?.ok_or(Error::NotFound)?;
        Self::import_secret(&bytes, params)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testutil::{keygen, params};
    use core::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemStore(RefCell<BTreeMap<String, Vec<u8>>>);

    impl SecretStore for MemStore {
        fn put(&self, key: &str, value: &[u8]) -> Result<()> {
            self.0.borrow_mut().insert(key.into(), value.to_vec());
            Ok(())
        }
        fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.borrow().get(key).map(|v| Zeroizing::new(v.clone())))
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.0.borrow_mut().remove(key);
            Ok(())
        }
    }

    #[test]
    fn shares_roundtrip_through_store() {
        let (c, s) = keygen(41);
        let store = MemStore::default();
        c.save(&store, "w1").unwrap();
        s.save(&store, "w1").unwrap();
        let c2 = ClientKeyShare::load(&store, "w1", &params()).unwrap();
        let s2 = ServerKeyShare::load(&store, "w1", &params()).unwrap();
        assert_eq!(c2.key_id(), c.key_id());
        assert_eq!(s2.key_id(), s.key_id());
        assert_eq!(
            ClientKeyShare::load(&store, "missing", &params()).unwrap_err(),
            Error::NotFound
        );
        store.delete(&client_key("w1")).unwrap();
        assert!(ClientKeyShare::load(&store, "w1", &params()).is_err());
    }

    #[test]
    fn save_never_overwrites() {
        let (c, s) = keygen(41);
        let (c_other, s_other) = keygen(42);
        let store = MemStore::default();
        c.save(&store, "w1").unwrap();
        s.save(&store, "w1").unwrap();
        assert_eq!(
            c_other.save(&store, "w1").unwrap_err(),
            Error::AlreadyExists
        );
        assert_eq!(
            s_other.save(&store, "w1").unwrap_err(),
            Error::AlreadyExists
        );
        let kept = ClientKeyShare::load(&store, "w1", &params()).unwrap();
        assert_eq!(kept.key_id(), c.key_id());
        c_other.replace(&store, "w1").unwrap();
        s_other.replace(&store, "w1").unwrap();
        let now = ClientKeyShare::load(&store, "w1", &params()).unwrap();
        assert_eq!(now.key_id(), c_other.key_id());
    }
}
