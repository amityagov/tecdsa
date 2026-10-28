//! Shared fixtures for unit tests: a reduced parameter profile and a ready setup.
extern crate std;

use core::cell::Cell;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use std::sync::OnceLock;

use crate::{
    keygen::{ClientKeyShare, ClientKeygen0, Clock, ServerKeyShare, ServerKeygen0},
    params::{PARAMS_128, Params, ParamsId},
    rsa::tough::{ToughSpec, sample_tough_prime},
    setup::{ServerSetupSecret, SetupData, VerifiedSetup, server_setup_with},
    zk::fac::FacParams,
};

pub struct TestClock(pub Cell<u64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
}

/// Reduced profile: small soundness, 1024-bit Paillier modulus (large enough for `u + x·v`).
pub fn params() -> Params {
    Params {
        id: ParamsId::P128,
        ell: 16,
        nu: 16,
        nu_leak: 16,
        n_rsa: 1024,
        n_client: 512,
        r_mod: 8,
        r_df: 16,
        r_df_star: 4,
        tough_count: 8,
        tough_bits: 64,
        ..PARAMS_128
    }
}

#[allow(dead_code)]
pub struct Fx {
    pub fac: FacParams,
    pub data: SetupData,
    pub sk: ServerSetupSecret,
    /// Verified setup with fixed-base tables, as the client uses it.
    pub setup: VerifiedSetup,
    /// The same view for the server (own data, no proof re-check).
    pub server_view: VerifiedSetup,
}

pub fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let p = params();
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let d_bits = p.n_rsa + 2 * p.ell + 2 * p.nu + 4;
        let d = sample_tough_prime(&mut rng, d_bits, 7, ToughSpec::SAFE).unwrap();
        let fac = FacParams::new(d.p().clone()).unwrap();
        let (data, sk) = server_setup_with(&mut rng, &p, &fac, [7u8; 32], b"server-A").unwrap();
        let setup = data.verify_with(&p, &fac).unwrap().with_tables();
        let server_view = data.assume_verified(&p).unwrap().with_tables();
        Fx {
            fac,
            data,
            sk,
            setup,
            server_view,
        }
    })
}

/// A complete keygen run.
#[allow(dead_code)]
pub fn keygen(seed: u64) -> (ClientKeyShare, ServerKeyShare) {
    let p = params();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let clock = TestClock(Cell::new(1_000));
    let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"client-1").unwrap();
    let (c1, m2) = ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"client-1", &m1).unwrap();
    let (server_share, m3) = s1.on_msg2(&mut rng, &m2).unwrap();
    let client_share = c1.on_msg3(&clock, &m3).unwrap();
    (client_share, server_share)
}
