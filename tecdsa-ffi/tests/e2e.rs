#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end through the FFI layer at full size: the server is the Rust core, the client is
//! the UniFFI API exactly as Swift sees it.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use rand_core::Rng;
use tecdsa_core::{
    keygen::ServerKeygen0, params::PARAMS_128, setup::server_setup, sign::ServerSign0,
};
use tecdsa_ffi::*;

#[derive(Default)]
struct Mem(Mutex<BTreeMap<String, Vec<u8>>>);

impl SecretStore for Mem {
    fn put(&self, key: String, value: Vec<u8>) -> Result<(), TecdsaError> {
        self.0.lock().unwrap().insert(key, value);
        Ok(())
    }
    fn get(&self, key: String) -> Result<Option<Vec<u8>>, TecdsaError> {
        Ok(self.0.lock().unwrap().get(&key).cloned())
    }
    fn delete(&self, key: String) -> Result<(), TecdsaError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
}

#[test]
fn keygen_and_sign_through_ffi() {
    let p = PARAMS_128;
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let (data, sk) = server_setup(&mut rng, &p, [3u8; 32], b"server").unwrap();
    let setup = ClientSetup::verify(data.to_bytes().unwrap(), Profile::P128).unwrap();
    assert_eq!(setup.hash(), data.hash().unwrap().to_vec());

    let store: Arc<dyn SecretStore> = Arc::new(Mem::default());
    let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &data, b"client").unwrap();
    let kg = ClientKeygen::start(setup.clone(), b"client".to_vec(), m1).unwrap();
    let (server_share, m3) = s1.on_msg2(&mut rng, &kg.msg2()).unwrap();
    let res = kg.finish(m3.clone(), "w1".into(), store.clone()).unwrap();
    assert!(matches!(
        kg.finish(m3, "w1".into(), store.clone()),
        Err(TecdsaError::SessionConsumed)
    ));
    assert_eq!(
        res.public_key,
        client_public_key(store.clone(), "w1".into(), Profile::P128).unwrap()
    );
    assert!(matches!(
        client_public_key(store.clone(), "nope".into(), Profile::P128),
        Err(TecdsaError::NotFound)
    ));

    let server_view = data.assume_verified(&p).unwrap().with_tables();
    let vk = VerifyingKey::from_sec1_bytes(&res.public_key).unwrap();
    for _ in 0..3 {
        let mut d = [0u8; 32];
        rng.fill_bytes(&mut d);
        let (st, m1) =
            ServerSign0::start(&mut rng, &server_view, &server_share, b"client", &d).unwrap();
        let m2 = client_sign(
            setup.clone(),
            store.clone(),
            "w1".into(),
            b"client".to_vec(),
            d.to_vec(),
            m1,
        )
        .unwrap();
        let (sig, m3) = st.finish(&server_view, sk.paillier_sk(), &m2).unwrap();
        let out =
            client_verify_signature(store.clone(), "w1".into(), Profile::P128, d.to_vec(), m3)
                .unwrap();
        assert_eq!(out.rs, sig.to_bytes().to_vec());
        vk.verify_prehash(&d, &Signature::from_slice(&out.rs).unwrap())
            .unwrap();
    }
    assert!(matches!(
        client_sign(
            setup,
            store,
            "w1".into(),
            b"client".to_vec(),
            vec![0; 31],
            vec![]
        ),
        Err(TecdsaError::InvalidInput)
    ));
}
