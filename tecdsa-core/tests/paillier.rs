//! Paillier / DF correctness on small random primes (full-size behaviour is covered by benches).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crypto_bigint::{BoxedUint, ConcatenatingMul};
use crypto_primes::{Flavor, random_prime};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tecdsa_core::{
    arith::{Modulus, SBig, sbig::SRange},
    df::DfParams,
    paillier::{PaillierPk, PaillierSk},
};

fn setup(rng: &mut ChaCha20Rng, prime_bits: u32) -> (PaillierPk, PaillierSk) {
    let p: BoxedUint = random_prime(rng, Flavor::Any, prime_bits);
    let q: BoxedUint = random_prime(rng, Flavor::Any, prime_bits);
    let n = p.concatenating_mul(&q);
    let n2m = Modulus::new(n.concatenating_mul(&n)).unwrap();
    // ρ = ρ₀^{2N} mod N²
    let rho0 = n2m.residue(&BoxedUint::from(0x1234_5678_9abc_def1u64));
    let two_n = SBig::from_uint(n.shl(1));
    let rho = n2m.pow_vartime(&rho0, &two_n).unwrap().retrieve();
    (
        PaillierPk::new(n, &rho).unwrap(),
        PaillierSk::new(p, q).unwrap(),
    )
}

#[test]
fn enc_dec_roundtrip_and_homomorphism() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (pk, sk) = setup(&mut rng, 256);
    let lam_bits = 64;
    for i in 0..20u64 {
        let m = SBig::from_i64((i as i64 - 10) * 1_000_003);
        let lam = SBig::random_in(&mut rng, SRange::pm_pow2(lam_bits));
        let c = pk.enc(&m, &lam, lam_bits).unwrap();
        let dec = sk.dec(&c).unwrap();
        let expect = m.rem_euclid(pk.mod_n().modulus());
        assert_eq!(dec.resize_to(expect.bits_precision()), expect);
    }
    // S = enc(u) · E^v  decrypts to u + x·v
    let x = SBig::from_i64(-424_242);
    let e = pk.enc(&x, &SBig::from_i64(77), 64).unwrap();
    let (u, v) = (SBig::from_i64(10_000_019), SBig::from_i64(31_337));
    let s = pk
        .enc(&u, &SBig::from_i64(5), 64)
        .unwrap()
        .mul(&pk.scale(&e, &v, 64).unwrap());
    let want = u.add(&x.mul(&v)).rem_euclid(pk.mod_n().modulus());
    assert_eq!(sk.dec(&s).unwrap().resize_to(want.bits_precision()), want);
}

trait ResizeTo {
    fn resize_to(&self, bits: u32) -> BoxedUint;
}
impl ResizeTo for BoxedUint {
    fn resize_to(&self, bits: u32) -> BoxedUint {
        // compare by value through bytes regardless of precision
        BoxedUint::from_be_slice_vartime(&self.to_be_bytes_trimmed_vartime()).widen_to(bits)
    }
}
trait WidenTo {
    fn widen_to(self, bits: u32) -> BoxedUint;
}
impl WidenTo for BoxedUint {
    fn widen_to(self, bits: u32) -> BoxedUint {
        let b = self.to_be_bytes_trimmed_vartime();
        let bits = bits.max(b.len() as u32 * 8);
        let mut v = alloc_zero(bits as usize / 8 - b.len());
        v.extend_from_slice(&b);
        BoxedUint::from_be_slice(&v, bits).unwrap()
    }
}
fn alloc_zero(n: usize) -> Vec<u8> {
    vec![0; n]
}

#[test]
fn ciphertext_validation() {
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let (pk, _) = setup(&mut rng, 128);
    let n2 = pk.mod_n2().modulus().as_ref().clone();
    assert!(
        pk.check_ciphertext(&BoxedUint::zero_with_precision(n2.bits_precision()))
            .is_err()
    );
    assert!(pk.check_ciphertext(&n2).is_err());
    let n_wide = pk.n().clone();
    let mut multiple = BoxedUint::zero_with_precision(n2.bits_precision());
    multiple = multiple.wrapping_add(&n_wide);
    assert!(pk.check_ciphertext(&multiple).is_err()); // gcd(N, N) ≠ 1
    assert!(
        pk.check_ciphertext(&BoxedUint::from(2u64).widen_to(n2.bits_precision()))
            .is_ok()
    );
}

#[test]
fn df_commit_ct_matches_vartime_with_and_without_tables() {
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let p: BoxedUint = random_prime(&mut rng, Flavor::Any, 256);
    let q: BoxedUint = random_prime(&mut rng, Flavor::Any, 256);
    let n = Modulus::new(p.concatenating_mul(&q)).unwrap();
    let mk = |v: u64| n.residue(&BoxedUint::from(v));
    let t = mk(0xdead_beef_1234_5678);
    let s1 = n.pow_vartime(&t, &SBig::from_i64(987_654_321)).unwrap();
    let s2 = n.pow_vartime(&t, &SBig::from_i64(123_456_789)).unwrap();
    let plain = DfParams::new(n.clone(), t.clone(), s1.clone(), s2.clone());
    let fast = DfParams::new(n, t, s1, s2).with_tables(256, 4);
    assert!(fast.tables_size_bytes() > 0);
    for _ in 0..10 {
        let r = SRange::pm_pow2(200);
        let (a, b, c) = (
            SBig::random_in(&mut rng, r),
            SBig::random_in(&mut rng, r),
            SBig::random_in(&mut rng, r),
        );
        let want = plain.commit_vartime(&a, &b, &c).unwrap().retrieve();
        assert_eq!(
            plain.commit_ct(&a, &b, &c, [200; 3]).unwrap().retrieve(),
            want
        );
        assert_eq!(
            fast.commit_ct(&a, &b, &c, [200; 3]).unwrap().retrieve(),
            want
        );
    }
}
