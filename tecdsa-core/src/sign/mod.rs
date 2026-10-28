//! Threshold signing (Protocol 3, spec §6.3): two rounds, S → C → S.
//!
//! 1. S → C `SignMsg1`: `R₂ = g^{k₂}`, `Y = X₁^{k₂}`.
//! 2. C → S `SignMsg2`: `R₁`, `R`, `S = enc(u; ρ^{λ₀})·E^v` and `ψ_sig`.
//! 3. S finishes: `r = 𝒳(R₁^{k₂+e})`, `σ = dec(S)·(k₂+e)^{-1}`, checked as a plain ECDSA signature,
//!    low-s normalized, with a recovery id. Optionally `SignMsg3` carries the result to C.
use k256::{
    ProjectivePoint, Scalar, U256,
    ecdsa::{
        RecoveryId, Signature as EcdsaSignature, VerifyingKey, signature::hazmat::PrehashVerifier,
    },
    elliptic_curve::{ops::Reduce, point::AffineCoordinates, scalar::IsHigh},
};
use rand_core::CryptoRng;

use crate::{
    curve::{decode_scalar, encode_point, encode_scalar},
    error::{Error, Result},
    hd::HdPath,
    params::Params,
    ssid::Ssid,
    transcript::Transcript,
};

pub mod client;
pub mod server;

pub use client::ClientSign;
pub use server::{ServerSign0, ServerSign1};

/// A finished ECDSA signature with low `s` and its recovery id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
    /// Bit 0: parity of `y(R)` (after low-s normalization); bit 1: `x(R) ≥ q`.
    pub recid: u8,
}

impl Signature {
    /// 64-byte `r ‖ s`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&encode_scalar(&self.r));
        out[32..].copy_from_slice(&encode_scalar(&self.s));
        out
    }

    pub fn to_ecdsa(&self) -> Result<EcdsaSignature> {
        EcdsaSignature::from_scalars(self.r, self.s).map_err(|_| Error::InvalidEncoding)
    }

    pub fn recovery_id(&self) -> Result<RecoveryId> {
        RecoveryId::from_byte(self.recid).ok_or(Error::InvalidEncoding)
    }
}

/// Digest `m` as a scalar (`bits2int` for a 256-bit digest, reduced mod `q`).
pub(crate) fn digest_scalar(digest: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(digest))
}

/// Rejects a digest that reduces to zero mod `q`. The reference implementation requires this
/// (its comments cite Claim 7.15 of the BAM paper); the claim itself was not re-checked here.
pub(crate) fn check_digest(digest: &[u8; 32]) -> Result<()> {
    if bool::from(k256::elliptic_curve::Field::is_zero(&digest_scalar(digest))) {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

/// The key a signature is made under and the client-share shift: `(X + δ·G, δ)` for an HD
/// path, `(X, 0)` without one.
pub(crate) fn signing_key(
    x_pub: &ProjectivePoint,
    hd: Option<&HdPath>,
) -> Result<(ProjectivePoint, Scalar)> {
    match hd {
        None => Ok((*x_pub, Scalar::ZERO)),
        Some(h) => {
            let delta = h.delta(x_pub)?;
            Ok((*x_pub + ProjectivePoint::GENERATOR * delta, delta))
        }
    }
}

/// Base transcript of a signing session for `role` (`"S"` or `"C"`).
pub(crate) fn tx_base(params: &Params, ssid: &Ssid, role: &str) -> Transcript {
    let mut t = Transcript::new("sign");
    t.append("params_id", &[params.id as u8]);
    t.append("ssid", &ssid.encode());
    t.append("role", role.as_bytes());
    t
}

/// `e = RO(X, R₁, R, m)` (domain `ro/sign-nonce`, bound to the ssid as well).
pub(crate) fn nonce_challenge(
    params: &Params,
    ssid: &Ssid,
    x_pub: &ProjectivePoint,
    r1: &ProjectivePoint,
    r: &ProjectivePoint,
    digest: &[u8; 32],
) -> Scalar {
    let mut t = Transcript::new("ro/sign-nonce");
    t.append("params_id", &[params.id as u8]);
    t.append("ssid", &ssid.encode());
    t.append("X", &encode_point(x_pub));
    t.append("R1", &encode_point(r1));
    t.append("R", &encode_point(r));
    t.append("m", digest);
    t.challenge("e").scalar()
}

/// Hedged nonce `k = H(fresh randomness ‖ secret ‖ context) mod q`, never zero (FR-G4).
pub(crate) fn hedged_nonce<R: CryptoRng + ?Sized>(
    rng: &mut R,
    label: &str,
    secret: &Scalar,
    context: &[u8],
) -> Scalar {
    let mut fresh = [0u8; 32];
    for i in 0u32.. {
        rng.fill_bytes(&mut fresh);
        let mut t = Transcript::new("hedged-nonce");
        t.append("label", label.as_bytes());
        t.append("rng", &fresh);
        t.append("secret", &encode_scalar(secret));
        t.append("ctx", context);
        t.append("ctr", &i.to_be_bytes());
        let k = t.challenge("k").scalar();
        if !bool::from(k256::elliptic_curve::Field::is_zero(&k)) {
            return k;
        }
    }
    Scalar::ONE
}

/// Plain ECDSA verification of `(r, s)` against `X` and the digest.
pub(crate) fn ecdsa_verify(
    x_pub: &ProjectivePoint,
    digest: &[u8; 32],
    sig: &Signature,
) -> Result<()> {
    let vk = VerifyingKey::from_affine(x_pub.to_affine()).map_err(|_| Error::VerificationFailed)?;
    vk.verify_prehash(digest, &sig.to_ecdsa()?)
        .map_err(|_| Error::VerificationFailed)
}

/// Low-s normalization and recovery id from the nonce point `R = (x, y)` (FR-G1, FR-G2).
pub(crate) fn finalize(r_point: &ProjectivePoint, r: Scalar, s: Scalar) -> Signature {
    let affine = r_point.to_affine();
    let y_odd: bool = affine.y_is_odd().into();
    let x_reduced = encode_scalar(&r) != affine.x().as_slice();
    let mut recid = u8::from(y_odd) | (u8::from(x_reduced) << 1);
    let mut s = s;
    if bool::from(s.is_high()) {
        s = -s;
        recid ^= 1;
    }
    Signature { r, s, recid }
}

/// Decodes `r ‖ s` canonical scalars and a recovery id.
pub(crate) fn decode_signature(r: &[u8], s: &[u8], recid: u8) -> Result<Signature> {
    let sig = Signature {
        r: decode_scalar(r)?,
        s: decode_scalar(s)?,
        recid,
    };
    sig.recovery_id()?;
    Ok(sig)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::hd::HdPath;
    use crate::{
        keygen::{ClientKeyShare, ServerKeyShare},
        testutil::{fx, keygen, params},
    };
    use k256::ecdsa::VerifyingKey;
    use rand_chacha::ChaCha8Rng;
    use rand_core::{Rng, SeedableRng};
    use std::{collections::BTreeSet, time::Instant, vec::Vec};

    /// One complete signing session; returns the server's signature and `SignMsg3`.
    fn sign_once(
        rng: &mut ChaCha8Rng,
        c: &ClientKeyShare,
        s: &ServerKeyShare,
        digest: &[u8; 32],
    ) -> (Signature, Vec<u8>) {
        let (s1, m1) =
            ServerSign0::start(rng, &fx().server_view, s, b"client-1", digest, None).unwrap();
        let m2 = ClientSign::respond(rng, &fx().setup, c, b"client-1", digest, &m1, None).unwrap();
        s1.finish(&fx().server_view, fx().sk.paillier_sk(), &m2)
            .unwrap()
    }

    fn digest(rng: &mut ChaCha8Rng) -> [u8; 32] {
        let mut d = [0u8; 32];
        rng.fill_bytes(&mut d);
        d
    }

    #[test]
    fn honest_signatures_verify_and_recover() {
        let (c, s) = keygen(21);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let vk = VerifyingKey::from_affine(c.public_key().to_affine()).unwrap();
        let mut parities = BTreeSet::new();
        for _ in 0..40 {
            let d = digest(&mut rng);
            let (sig, m3) = sign_once(&mut rng, &c, &s, &d);
            // an ordinary ECDSA signature
            vk.verify_prehash(&d, &sig.to_ecdsa().unwrap()).unwrap();
            // low-s (BIP-62 / EIP-2)
            assert!(!bool::from(sig.s.is_high()));
            // the recovery id recovers X
            let rec = VerifyingKey::recover_from_prehash(
                &d,
                &sig.to_ecdsa().unwrap(),
                sig.recovery_id().unwrap(),
            )
            .unwrap();
            assert_eq!(rec, vk);
            // the client accepts the server's SignMsg3
            assert_eq!(
                ClientSign::verify_final(&params(), &c, &d, &m3, None).unwrap(),
                sig
            );
            parities.insert(sig.recid & 1);
        }
        assert_eq!(parities.len(), 2, "both y parities must occur");
    }

    #[test]
    fn same_digest_gives_fresh_nonces() {
        let (c, s) = keygen(22);
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let d = digest(&mut rng);
        let (a, _) = sign_once(&mut rng, &c, &s, &d);
        let (b, _) = sign_once(&mut rng, &c, &s, &d);
        assert_ne!(a.r, b.r);
    }

    #[test]
    fn corrupted_messages_are_rejected() {
        let (c, s) = keygen(23);
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let d = digest(&mut rng);
        let (s1, m1) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d, None).unwrap();

        for i in [4usize, 10, 30, 36, 50, m1.len() - 1] {
            let mut bad = m1.clone();
            bad[i] ^= 1;
            assert!(
                ClientSign::respond(&mut rng, &fx().setup, &c, b"client-1", &d, &bad, None)
                    .is_err(),
                "msg1 flip {i}"
            );
        }
        let m2 =
            ClientSign::respond(&mut rng, &fx().setup, &c, b"client-1", &d, &m1, None).unwrap();
        let positions = [
            4usize,
            20,
            40,
            80,
            120,
            200,
            400,
            m2.len() / 2,
            m2.len() - 60,
            m2.len() - 1,
        ];
        for i in positions.iter().copied().filter(|i| *i < m2.len()) {
            let mut bad = m2.clone();
            bad[i] ^= 1;
            let r = s1
                .test_clone()
                .finish(&fx().server_view, fx().sk.paillier_sk(), &bad);
            assert!(r.is_err(), "msg2 flip {i}");
        }
        assert!(
            s1.test_clone()
                .finish(
                    &fx().server_view,
                    fx().sk.paillier_sk(),
                    &m2[..m2.len() - 1]
                )
                .is_err()
        );
        assert!(
            s1.finish(&fx().server_view, fx().sk.paillier_sk(), &m2)
                .is_ok()
        );
    }

    #[test]
    fn session_binding() {
        let (c, s) = keygen(24);
        let (c_other, _) = keygen(25);
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        let (d1, d2) = (digest(&mut rng), digest(&mut rng));

        // client signs another digest than the server expects
        let (s1, m1) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d1, None).unwrap();
        let m2 =
            ClientSign::respond(&mut rng, &fx().setup, &c, b"client-1", &d2, &m1, None).unwrap();
        assert!(
            s1.finish(&fx().server_view, fx().sk.paillier_sk(), &m2)
                .is_err()
        );

        // client with another id
        let (s1, m1) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d1, None).unwrap();
        let m2 =
            ClientSign::respond(&mut rng, &fx().setup, &c, b"client-X", &d1, &m1, None).unwrap();
        assert!(
            s1.finish(&fx().server_view, fx().sk.paillier_sk(), &m2)
                .is_err()
        );

        // SignMsg2 of an earlier session
        let (_, m1a) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d1, None).unwrap();
        let m2a =
            ClientSign::respond(&mut rng, &fx().setup, &c, b"client-1", &d1, &m1a, None).unwrap();
        let (s1b, _) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d1, None).unwrap();
        assert!(
            s1b.finish(&fx().server_view, fx().sk.paillier_sk(), &m2a)
                .is_err()
        );

        // a client holding another key rejects the server's SignMsg1 (Y ≠ R₂^{x₁})
        let (_, m1) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d1, None).unwrap();
        assert!(
            ClientSign::respond(&mut rng, &fx().setup, &c_other, b"client-1", &d1, &m1, None)
                .is_err()
        );
    }

    fn hd(chain: u8, path: &[u32]) -> HdPath {
        HdPath::new([chain; 32], path.to_vec()).unwrap()
    }

    #[test]
    fn hd_signatures_verify_under_the_derived_key_only() {
        let (c, s) = keygen(28);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let x = VerifyingKey::from_affine(c.public_key().to_affine()).unwrap();
        for path in [
            hd(1, &[0]),
            hd(2, &[44, 0, 0, 0, 7]),
            hd(3, &[5, 6, 1_000_000]),
        ] {
            let d = digest(&mut rng);
            let (st, m1) = ServerSign0::start(
                &mut rng,
                &fx().server_view,
                &s,
                b"client-1",
                &d,
                Some(&path),
            )
            .unwrap();
            let m2 =
                ClientSign::respond(&mut rng, &fx().setup, &c, b"client-1", &d, &m1, Some(&path))
                    .unwrap();
            let (sig, m3) = st
                .finish(&fx().server_view, fx().sk.paillier_sk(), &m2)
                .unwrap();

            let derived = path.delta(c.public_key()).unwrap();
            let derived_pk = VerifyingKey::from_affine(
                (*c.public_key() + ProjectivePoint::GENERATOR * derived).to_affine(),
            )
            .unwrap();
            let ecdsa = sig.to_ecdsa().unwrap();
            derived_pk.verify_prehash(&d, &ecdsa).unwrap();
            assert!(
                x.verify_prehash(&d, &ecdsa).is_err(),
                "must not verify under the master key"
            );
            let rec =
                VerifyingKey::recover_from_prehash(&d, &ecdsa, sig.recovery_id().unwrap()).unwrap();
            assert_eq!(rec, derived_pk);
            assert_eq!(
                ClientSign::verify_final(&params(), &c, &d, &m3, Some(&path)).unwrap(),
                sig
            );
            assert!(ClientSign::verify_final(&params(), &c, &d, &m3, None).is_err());
        }
    }

    #[test]
    fn hd_paths_must_agree() {
        let (c, s) = keygen(29);
        let mut rng = ChaCha8Rng::seed_from_u64(8);
        let d = digest(&mut rng);
        let p = hd(1, &[1, 2]);
        let (_, m1) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d, Some(&p)).unwrap();
        // other path, other chain code, or none at all: the client rejects SignMsg1 (Y ≠ R₂^{x₁'})
        for other in [Some(hd(1, &[2, 1])), Some(hd(9, &[1, 2])), None] {
            let r = ClientSign::respond(
                &mut rng,
                &fx().setup,
                &c,
                b"client-1",
                &d,
                &m1,
                other.as_ref(),
            );
            assert!(r.is_err());
        }
        // and the other way round
        let (_, m1) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d, None).unwrap();
        assert!(
            ClientSign::respond(&mut rng, &fx().setup, &c, b"client-1", &d, &m1, Some(&p)).is_err()
        );
    }

    #[test]
    fn zero_digest_is_rejected_by_both_sides() {
        let (c, s) = keygen(27);
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        let zero = [0u8; 32];
        assert!(
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &zero, None).is_err()
        );
        // digest equal to the group order reduces to zero as well
        let order = crate::curve::order();
        let mut n = [0u8; 32];
        let bytes = order.to_be_bytes();
        n.copy_from_slice(&bytes[bytes.len() - 32..]);
        assert!(
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &n, None).is_err()
        );
        let d = digest(&mut rng);
        let (_, m1) =
            ServerSign0::start(&mut rng, &fx().server_view, &s, b"client-1", &d, None).unwrap();
        assert!(
            ClientSign::respond(&mut rng, &fx().setup, &c, b"client-1", &zero, &m1, None).is_err()
        );
    }

    #[test]
    fn signmsg3_is_checked_by_the_client() {
        let (c, s) = keygen(26);
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let d = digest(&mut rng);
        let (sig, m3) = sign_once(&mut rng, &c, &s, &d);
        let p = params();
        assert!(ClientSign::verify_final(&p, &c, &digest(&mut rng), &m3, None).is_err());
        let mut bad = m3.clone();
        let n = bad.len();
        bad[n - 5] ^= 1; // inside s
        assert!(ClientSign::verify_final(&p, &c, &d, &bad, None).is_err());
        let wrong_recid = crate::messages::SignMsg3 {
            r: encode_scalar(&sig.r).to_vec(),
            s: encode_scalar(&sig.s).to_vec(),
            recid: sig.recid ^ 1,
        }
        .encode(&p)
        .unwrap();
        assert!(ClientSign::verify_final(&p, &c, &d, &wrong_recid, None).is_err());
    }

    #[test]
    #[ignore = "long: run with --release --ignored; N from TECDSA_SIGN_COUNT (default 10000)"]
    fn many_signatures_reduced() {
        let n: usize = std::env::var("TECDSA_SIGN_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let (c, s) = keygen(30);
        let vk = VerifyingKey::from_affine(c.public_key().to_affine()).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(30);
        let t = Instant::now();
        for _ in 0..n {
            let d = digest(&mut rng);
            let (sig, _) = sign_once(&mut rng, &c, &s, &d);
            vk.verify_prehash(&d, &sig.to_ecdsa().unwrap()).unwrap();
            let rec = VerifyingKey::recover_from_prehash(
                &d,
                &sig.to_ecdsa().unwrap(),
                sig.recovery_id().unwrap(),
            )
            .unwrap();
            assert_eq!(rec, vk);
        }
        std::eprintln!("{n} signatures in {:?}", t.elapsed());
    }

    #[test]
    #[ignore = "full-size: run with --release --ignored --nocapture"]
    fn full_size_sign() {
        use crate::{params::PARAMS_128, setup::server_setup};
        let p = PARAMS_128;
        let mut rng = ChaCha8Rng::seed_from_u64(77);
        let (data, sk) = server_setup(&mut rng, &p, [1u8; 32], b"server").unwrap();
        let client_view = data.verify(&p).unwrap().with_tables();
        let server_view = data.assume_verified(&p).unwrap().with_tables();
        std::eprintln!("tables: {} KiB", client_view.tables_size_bytes() / 1024);
        let clock = crate::testutil::TestClock(core::cell::Cell::new(0));
        let (s1, m1) = crate::keygen::ServerKeygen0::start(&mut rng, &p, &data, b"client").unwrap();
        let (c1, m2) =
            crate::keygen::ClientKeygen0::on_msg1(&mut rng, &clock, &client_view, b"client", &m1)
                .unwrap();
        let (s_share, m3) = s1.on_msg2(&mut rng, &m2).unwrap();
        let c_share = c1.on_msg3(&clock, &m3).unwrap();
        let (mut tc, mut ts1, mut ts3) = (Vec::new(), Vec::new(), Vec::new());
        let mut size2 = 0;
        let count: usize = std::env::var("TECDSA_FULL_SIGN_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        for _ in 0..count {
            let d = digest(&mut rng);
            let t = Instant::now();
            let (st, m1) =
                ServerSign0::start(&mut rng, &server_view, &s_share, b"client", &d, None).unwrap();
            ts1.push(t.elapsed());
            let t = Instant::now();
            let m2 =
                ClientSign::respond(&mut rng, &client_view, &c_share, b"client", &d, &m1, None)
                    .unwrap();
            tc.push(t.elapsed());
            size2 = m2.len();
            let t = Instant::now();
            let (sig, _) = st.finish(&server_view, sk.paillier_sk(), &m2).unwrap();
            ts3.push(t.elapsed());
            let vk = VerifyingKey::from_affine(c_share.public_key().to_affine()).unwrap();
            vk.verify_prehash(&d, &sig.to_ecdsa().unwrap()).unwrap();
        }
        let med = |v: &mut Vec<core::time::Duration>| {
            v.sort();
            v[v.len() / 2]
        };
        std::eprintln!(
            "sign (median of {count}): S1 {:?} | client {:?} (SignMsg2 {size2} B) | S3 {:?}",
            med(&mut ts1),
            med(&mut tc),
            med(&mut ts3)
        );
    }
}
