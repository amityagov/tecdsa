//! Distributed key generation (Protocol 2, spec §6.2): four messages, S–C.
//!
//! 1. S → C `KgMsg1`: nonce and commitment `B = RO(ssid, S, X₂)`.
//! 2. C → S `KgMsg2`: `X₁`, ephemeral DF tuple, `ψ_df*`, `ψ_dlog`.
//! 3. S → C `KgMsg3`: `X₂`, `E`, `ψ_dlenc`.
//! 4. C verifies and outputs.
use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    arith::monty::Modulus,
    curve::{decode_point, decode_scalar, encode_point, encode_scalar},
    error::{Error, Result},
    params::Params,
    ssid::Ssid,
    transcript::{Transcript, uint_from_be, uint_to_be},
    zk::df::DfStatement,
};

pub mod client;
pub mod server;

pub use client::{ClientKeygen0, ClientKeygen1};
pub use server::{ServerKeygen0, ServerKeygen1};

/// The client must finish within this time after sending `KgMsg2` (spec §6.2, step 2).
pub const KEYGEN_TIMEOUT_MS: u64 = 60_000;

/// Monotonic millisecond clock supplied by the application (the core is `no_std`).
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// Base transcript of one keygen session for `role` (`"S"` or `"C"`).
pub(crate) fn tx_base(params: &Params, ssid: &Ssid, role: &str) -> Transcript {
    let mut t = Transcript::new("keygen");
    t.append("params_id", &[params.id as u8]);
    t.append("ssid", &ssid.encode());
    t.append("role", role.as_bytes());
    t
}

/// `B = RO(ssid, S, X₂)` (domain `ro/kg-commit`, spec §10.3).
pub(crate) fn commitment(params: &Params, ssid: &Ssid, x2_pub: &ProjectivePoint) -> [u8; 32] {
    let mut t = Transcript::new("ro/kg-commit");
    t.append("params_id", &[params.id as u8]);
    t.append("ssid", &ssid.encode());
    t.append("S", ssid.server_id());
    t.append("X2", &encode_point(x2_pub));
    t.challenge("B").seed()
}

/// Fixed-width element `< bound` (canonical) as an integer.
pub(crate) fn canonical_uint(bytes: &[u8], len: usize, bound: &BoxedUint) -> Result<BoxedUint> {
    if bytes.len() != len {
        return Err(Error::InvalidEncoding);
    }
    let x = uint_from_be(bytes, bound.bits_precision())?;
    let b = crate::arith::sbig::resized(bound, x.bits_precision());
    if x.cmp_vartime(&b) != core::cmp::Ordering::Less {
        return Err(Error::OutOfRange);
    }
    Ok(x)
}

/// Decodes the client's ephemeral tuple `(M̂, v, u1, u2)` with strict length and range checks.
pub(crate) fn decode_client_tuple(
    params: &Params,
    m_hat: &[u8],
    v: &[u8],
    u1: &[u8],
    u2: &[u8],
) -> Result<DfStatement> {
    let len = params.n_client as usize / 8;
    if m_hat.len() != len {
        return Err(Error::InvalidEncoding);
    }
    let m = uint_from_be(m_hat, params.n_client)?;
    if m.bits_vartime() != params.n_client {
        return Err(Error::OutOfRange);
    }
    Modulus::new(m.clone())?;
    let vv = canonical_uint(v, len, &m)?;
    let a = canonical_uint(u1, len, &m)?;
    let b = canonical_uint(u2, len, &m)?;
    DfStatement::client(&m, &vv, &a, &b)
}

pub(crate) fn encode_client_tuple(params: &Params, st: &DfStatement) -> Result<[Vec<u8>; 4]> {
    let len = params.n_client as usize / 8;
    let enc = |r: &crate::arith::monty::Residue| uint_to_be(&r.retrieve(), len);
    Ok([
        uint_to_be(st.n_hat.modulus().as_ref(), len)?,
        enc(&st.t)?,
        enc(&st.s1)?,
        enc(&st.s2)?,
    ])
}

fn key_id(x_pub: &ProjectivePoint, e: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(encode_point(x_pub));
    h.update(e);
    h.finalize().into()
}

const SHARE_VERSION: u8 = 0x01;

macro_rules! key_share {
    ($name:ident, $field:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(ZeroizeOnDrop)]
        pub struct $name {
            $field: Scalar,
            #[zeroize(skip)]
            x_pub: ProjectivePoint,
            /// `E` as fixed-width big-endian (`⌈2·n_rsa/8⌉` bytes).
            #[zeroize(skip)]
            e: Vec<u8>,
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(***)"))
            }
        }

        impl $name {
            pub(crate) fn new($field: Scalar, x_pub: ProjectivePoint, e: Vec<u8>) -> Self {
                Self { $field, x_pub, e }
            }
            /// Joint public key `X = X₁·X₂`.
            pub fn public_key(&self) -> &ProjectivePoint {
                &self.x_pub
            }
            /// The Paillier ciphertext `E` (fixed-width bytes).
            pub fn e_bytes(&self) -> &[u8] {
                &self.e
            }
            /// `SHA-256(X ‖ E)`, the `key_id` of sign sessions.
            pub fn key_id(&self) -> [u8; 32] {
                key_id(&self.x_pub, &self.e)
            }
            #[allow(dead_code)]
            pub(crate) fn secret(&self) -> &Scalar {
                &self.$field
            }
            /// Explicit export for a `SecretStore`: `version ‖ share(32) ‖ X(33) ‖ E`.
            pub fn export_secret(&self) -> Zeroizing<Vec<u8>> {
                let mut out = Zeroizing::new(Vec::with_capacity(1 + 32 + 33 + self.e.len()));
                out.push(SHARE_VERSION);
                out.extend_from_slice(&encode_scalar(&self.$field));
                out.extend_from_slice(&encode_point(&self.x_pub));
                out.extend_from_slice(&self.e);
                out
            }
            pub fn import_secret(bytes: &[u8], params: &Params) -> Result<Self> {
                let elen = (2 * params.n_rsa as usize).div_ceil(8);
                if bytes.len() != 1 + 32 + 33 + elen || bytes[0] != SHARE_VERSION {
                    return Err(Error::InvalidEncoding);
                }
                Ok(Self {
                    $field: decode_scalar(&bytes[1..33])?,
                    x_pub: decode_point(&bytes[33..66])?,
                    e: bytes[66..].to_vec(),
                })
            }
        }
    };
}

key_share!(
    ClientKeyShare,
    x1,
    "Client output of keygen: `x₁`, `X`, `E`."
);
key_share!(
    ServerKeyShare,
    x2,
    "Server output of keygen: `x₂ = x₂′ mod q`, `X`, `E`."
);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{
        arith::sbig::SBig,
        params::PARAMS_128,
        testutil::{TestClock, fx, params},
    };
    use core::cell::Cell;
    use k256::ProjectivePoint;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn run(seed: u64) -> (ClientKeyShare, ServerKeyShare) {
        let p = params();
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let clock = TestClock(Cell::new(1_000));
        let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"client-1").unwrap();
        let (c1, m2) =
            ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"client-1", &m1).unwrap();
        let (server_share, m3) = s1.on_msg2(&mut rng, &m2).unwrap();
        let client_share = c1.on_msg3(&clock, &m3).unwrap();
        (client_share, server_share)
    }

    #[test]
    fn honest_keygen() {
        let (c, s) = run(5);
        assert_eq!(c.public_key(), s.public_key());
        assert_eq!(c.e_bytes(), s.e_bytes());
        assert_eq!(c.key_id(), s.key_id());
        let sum = *c.secret() + *s.secret();
        assert_eq!(ProjectivePoint::GENERATOR * sum, *c.public_key());
        // E decrypts to x₂′ (mod N), which reduces to x₂ mod q
        let pk = fx().data.paillier_pk().unwrap();
        let e = pk
            .check_ciphertext(&uint_from_be(s.e_bytes(), 1024).unwrap())
            .unwrap();
        let m = fx().sk.paillier_sk().dec(&e).unwrap();
        // signed interpretation: values above N/2 are negative
        let n = pk.n().clone();
        let half = n.shr_vartime(1).unwrap();
        let signed = if m.cmp_vartime(&half) == core::cmp::Ordering::Greater {
            SBig::from_uint(crate::arith::sbig::resized(&m, n.bits_precision()))
                .sub(&SBig::from_uint(n))
        } else {
            SBig::from_uint(m)
        };
        assert_eq!(crate::curve::sbig_to_scalar(&signed).unwrap(), *s.secret());
        assert_eq!(std::format!("{c:?}"), "ClientKeyShare(***)");
        // export / import
        let back = ServerKeyShare::import_secret(&s.export_secret(), &params()).unwrap();
        assert_eq!(back.key_id(), s.key_id());
        assert_eq!(*back.secret(), *s.secret());
        assert!(ClientKeyShare::import_secret(&c.export_secret()[1..], &params()).is_err());
    }

    #[test]
    fn two_sessions_differ() {
        let (a, _) = run(5);
        let (b, _) = run(6);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn tampered_messages_are_rejected() {
        let p = params();
        let clock = TestClock(Cell::new(0));
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"client-1").unwrap();
        let (c1, m2) =
            ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"client-1", &m1).unwrap();

        // KgMsg2 corruption: server must reject (decode or verification).
        let positions = [
            4,
            20,
            60,
            100,
            200,
            300,
            m2.len() / 2,
            m2.len() - 40,
            m2.len() - 1,
        ];
        for &i in positions.iter().filter(|i| **i < m2.len()) {
            let mut bad = m2.clone();
            bad[i] ^= 0x01;
            let s = clone_server_state(&s1);
            assert!(s.on_msg2(&mut rng, &bad).is_err(), "msg2 flip at {i}");
        }
        // truncated / extended / wrong envelope
        assert!(
            clone_server_state(&s1)
                .on_msg2(&mut rng, &m2[..m2.len() - 1])
                .is_err()
        );
        let mut longer = m2.clone();
        longer.push(0);
        assert!(clone_server_state(&s1).on_msg2(&mut rng, &longer).is_err());
        let mut wrong_type = m2.clone();
        wrong_type[3] = 3;
        assert!(
            clone_server_state(&s1)
                .on_msg2(&mut rng, &wrong_type)
                .is_err()
        );

        let (_, m3) = s1.on_msg2(&mut rng, &m2).unwrap();
        // KgMsg3 corruption: client must reject.
        let positions = [
            4,
            10,
            40,
            100,
            200,
            300,
            m3.len() / 2,
            m3.len() - 100,
            m3.len() - 1,
        ];
        for &i in positions.iter().filter(|i| **i < m3.len()) {
            let mut bad = m3.clone();
            bad[i] ^= 0x01;
            assert!(
                clone_client_state(&c1).on_msg3(&clock, &bad).is_err(),
                "msg3 flip at {i}"
            );
        }
        assert!(c1.on_msg3(&clock, &m3).is_ok());
    }

    #[test]
    fn timer_and_session_binding() {
        let p = params();
        let mut rng = ChaCha8Rng::seed_from_u64(10);
        let clock = TestClock(Cell::new(0));
        let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"client-1").unwrap();
        let (c1, m2) =
            ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"client-1", &m1).unwrap();
        let (_, m3) = s1.on_msg2(&mut rng, &m2).unwrap();

        // exactly at the limit passes, one millisecond later fails
        clock.0.set(KEYGEN_TIMEOUT_MS);
        assert!(clone_client_state(&c1).on_msg3(&clock, &m3).is_ok());
        clock.0.set(KEYGEN_TIMEOUT_MS + 1);
        assert_eq!(
            clone_client_state(&c1).on_msg3(&clock, &m3).unwrap_err(),
            Error::Timeout
        );

        // a client with another id cannot use the session's messages (ssid mismatch)
        clock.0.set(0);
        let (s2, m1b) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"client-1").unwrap();
        let (c2, m2b) =
            ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"client-OTHER", &m1b).unwrap();
        assert!(s2.on_msg2(&mut rng, &m2b).is_err());
        drop(c2);

        // KgMsg3 of another session is rejected by the client
        let (s3, m1c) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"client-1").unwrap();
        let (c3, m2c) =
            ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"client-1", &m1c).unwrap();
        let (_, m3c) = s3.on_msg2(&mut rng, &m2c).unwrap();
        assert!(c3.on_msg3(&clock, &m3).is_err());
        let _ = m3c;
    }

    // States are consumed by value in the API; tests need copies to try many corruptions.
    fn clone_server_state(s: &ServerKeygen1) -> ServerKeygen1 {
        s.test_clone()
    }
    fn clone_client_state(s: &ClientKeygen1) -> ClientKeygen1 {
        s.test_clone()
    }

    #[test]
    #[ignore = "full-size: run with --release --ignored --nocapture"]
    fn full_size_keygen() {
        use crate::setup::server_setup;
        use std::time::Instant;
        let p = PARAMS_128;
        let mut rng = ChaCha8Rng::seed_from_u64(77);
        let (data, _sk) = server_setup(&mut rng, &p, [1u8; 32], b"server").unwrap();
        let setup = data.verify(&p).unwrap();
        let clock = TestClock(Cell::new(0));
        let t = Instant::now();
        let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &data, b"client").unwrap();
        let t_s1 = t.elapsed();
        let t = Instant::now();
        let (c1, m2) = ClientKeygen0::on_msg1(&mut rng, &clock, &setup, b"client", &m1).unwrap();
        let t_c = t.elapsed();
        let t = Instant::now();
        let (ss, m3) = s1.on_msg2(&mut rng, &m2).unwrap();
        let t_s2 = t.elapsed();
        let t = Instant::now();
        let cs = c1.on_msg3(&clock, &m3).unwrap();
        let t_c2 = t.elapsed();
        assert_eq!(cs.public_key(), ss.public_key());
        std::eprintln!(
            "keygen: S1 {t_s1:?} ({} B) | C step 2 {t_c:?} ({} B) | S step 3 {t_s2:?} ({} B) | C step 4 {t_c2:?}",
            m1.len(),
            m2.len(),
            m3.len()
        );
    }
}
