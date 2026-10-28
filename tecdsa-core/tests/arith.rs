//! Property tests of `arith` against `dashu-int` as an oracle.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crypto_bigint::{BoxedUint, NonZero};
use dashu_base::{RemEuclid, UnsignedAbs};
use dashu_int::{IBig, UBig, fast_div::ConstDivisor};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use tecdsa_core::arith::{
    Modulus, SBig, fixed_base::FixedBase, monty::jacobi_vartime, multiexp::multiexp_vartime,
    sbig::SRange,
};

fn bu(x: &UBig, bits: u32) -> BoxedUint {
    let b = x.to_be_bytes();
    BoxedUint::from_be_slice(&b, bits).unwrap()
}

fn sb(x: &IBig, bits: u32) -> SBig {
    let m = bu(&x.clone().unsigned_abs(), bits);
    let s = SBig::from_uint(m);
    if *x < IBig::ZERO { s.negate() } else { s }
}

fn to_ibig(s: &SBig) -> IBig {
    let m = UBig::from_be_bytes(&s.mag().to_be_bytes());
    let v = IBig::from(m);
    if bool::from(s.is_neg()) { -v } else { v }
}

fn ibig_strategy() -> impl Strategy<Value = IBig> {
    (prop::collection::vec(any::<u8>(), 0..48), any::<bool>()).prop_map(|(b, neg)| {
        let v = IBig::from(UBig::from_be_bytes(&b));
        if neg { -v } else { v }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn sbig_add_sub_mul(a in ibig_strategy(), b in ibig_strategy()) {
        let (x, y) = (sb(&a, 512), sb(&b, 512));
        prop_assert_eq!(to_ibig(&x.add(&y)), &a + &b);
        prop_assert_eq!(to_ibig(&x.sub(&y)), &a - &b);
        prop_assert_eq!(to_ibig(&x.mul(&y)), &a * &b);
        prop_assert_eq!(to_ibig(&x.negate()), -&a);
    }

    #[test]
    fn sbig_rem_euclid(a in ibig_strategy(), m in 2u64..u64::MAX) {
        let x = sb(&a, 512);
        let modulus = NonZero::new(BoxedUint::from(m)).into_option().unwrap();
        let r = x.rem_euclid(&modulus);
        let expect = a.rem_euclid(&IBig::from(m));
        prop_assert_eq!(UBig::from_be_bytes(&r.to_be_bytes()), expect);
    }

    #[test]
    fn sbig_bytes_roundtrip(a in ibig_strategy()) {
        let x = sb(&a, 512);
        let range = SRange::pm_pow2(400);
        match x.to_bytes(range) {
            Ok(bytes) => {
                let back = SBig::from_bytes(&bytes, range).unwrap();
                prop_assert_eq!(to_ibig(&back), a);
            }
            Err(_) => prop_assert!(!x.in_range(range)),
        }
    }
}

#[test]
fn sbig_range_boundaries() {
    let n = 16u32;
    let r = SRange::pm_pow2(n);
    let top = IBig::from(1u32 << (n - 1));
    assert!(sb(&top, 64).in_range(r)); // +2^{n-1}
    assert!(!sb(&(&top + 1), 64).in_range(r));
    assert!(sb(&(-&top + 1), 64).in_range(r)); // −2^{n−1}+1
    assert!(!sb(&(-&top), 64).in_range(r));
    assert!(SBig::from_bytes(&[1, 0, 0], r).is_err()); // negative zero
}

#[test]
fn sbig_random_in_range() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let n = 12;
    let r = SRange::pm_pow2(n);
    let (mut lo, mut hi) = (IBig::ZERO, IBig::ZERO);
    for _ in 0..50_000 {
        let v = to_ibig(&SBig::random_in(&mut rng, r));
        assert!(sb(&v, 64).in_range(r));
        lo = lo.min(v.clone());
        hi = hi.max(v);
    }
    assert_eq!(hi, IBig::from(1u32 << (n - 1)));
    assert_eq!(lo, -IBig::from(1u32 << (n - 1)) + 1);
}

fn random_odd(rng: &mut ChaCha20Rng, bits: u32) -> UBig {
    let mut b = vec![0u8; (bits / 8) as usize];
    rng.fill_bytes(&mut b);
    b[0] |= 0x80;
    *b.last_mut().unwrap() |= 1;
    UBig::from_be_bytes(&b)
}

fn rand_signed(rng: &mut ChaCha20Rng, bits: u32) -> IBig {
    let mut b = vec![0u8; (bits / 8) as usize];
    rng.fill_bytes(&mut b);
    let v = IBig::from(UBig::from_be_bytes(&b));
    if rng.next_u32() & 1 == 1 { -v } else { v }
}

fn oracle_pow(m: &UBig, base: &UBig, e: &IBig) -> UBig {
    let ring = ConstDivisor::new(m.clone());
    let b = ring.reduce(base.clone());
    let b = if *e < IBig::ZERO { b.inv().unwrap() } else { b };
    b.pow(&e.clone().unsigned_abs()).residue()
}

#[test]
fn pow_and_multiexp_and_fixed_base() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    for round in 0..40 {
        let bits = if round % 2 == 0 { 512 } else { 1024 };
        let mut n = random_odd(&mut rng, bits);
        // keep base invertible: odd modulus, retry bases until gcd = 1 via oracle inverse
        let modulus = Modulus::new(bu(&n, bits)).unwrap();
        let mut bases = vec![];
        while bases.len() < 4 {
            let b = random_odd(&mut rng, bits - 8) % &n;
            if ConstDivisor::new(n.clone())
                .reduce(b.clone())
                .inv()
                .is_some()
            {
                bases.push(b);
            }
        }
        n = n.clone();
        let exps: Vec<IBig> = (0..4).map(|_| rand_signed(&mut rng, 256)).collect();
        let rb: Vec<_> = bases
            .iter()
            .map(|b| modulus.residue(&bu(b, bits)))
            .collect();
        let se: Vec<_> = exps.iter().map(|e| sb(e, 320)).collect();

        // pow
        for i in 0..4 {
            let want = oracle_pow(&n, &bases[i], &exps[i]);
            let got = modulus.pow_ct(&rb[i], &se[i], 256).unwrap().retrieve();
            assert_eq!(UBig::from_be_bytes(&got.to_be_bytes()), want, "pow_ct");
            let got = modulus.pow_vartime(&rb[i], &se[i]).unwrap().retrieve();
            assert_eq!(UBig::from_be_bytes(&got.to_be_bytes()), want, "pow_vartime");
        }
        // multiexp with 2..=4 terms
        for k in 2..=4 {
            let terms: Vec<_> = rb.iter().zip(&se).take(k).collect();
            let got = multiexp_vartime(&modulus, &terms).unwrap().retrieve();
            let ring = ConstDivisor::new(n.clone());
            let mut want = ring.reduce(UBig::ONE);
            for i in 0..k {
                want *= ring.reduce(oracle_pow(&n, &bases[i], &exps[i]));
            }
            assert_eq!(
                UBig::from_be_bytes(&got.to_be_bytes()),
                want.residue(),
                "multiexp k={k}"
            );
        }
        // fixed base
        let fb = FixedBase::new(&modulus, &rb[0], 256, 4);
        let want = oracle_pow(&n, &bases[0], &exps[0]);
        let g1 = fb.pow_vartime(&se[0]).unwrap().retrieve();
        let g2 = fb.pow_ct(&se[0]).unwrap().retrieve();
        assert_eq!(
            UBig::from_be_bytes(&g1.to_be_bytes()),
            want,
            "fixed vartime"
        );
        assert_eq!(UBig::from_be_bytes(&g2.to_be_bytes()), want, "fixed ct");
    }
}

#[test]
fn pow_edge_cases() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let n = random_odd(&mut rng, 512);
    let m = Modulus::new(bu(&n, 512)).unwrap();
    let base = m.residue(&bu(&UBig::from(3u8), 512));
    let zero = SBig::zero(64);
    assert_eq!(
        m.pow_vartime(&base, &zero).unwrap().retrieve(),
        m.one().retrieve()
    );
    assert_eq!(
        m.pow_ct(&base, &zero, 64).unwrap().retrieve(),
        m.one().retrieve()
    );
}

#[test]
fn jacobi_matches_euler() {
    // secp256k1 field prime
    let p = UBig::from_str_radix(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .unwrap();
    let pb = bu(&p, 256);
    let ring = ConstDivisor::new(p.clone());
    let e = (&p - 1u8) >> 1;
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for _ in 0..500 {
        let a = random_odd(&mut rng, 248) % &p;
        let euler = ring.reduce(a.clone()).pow(&e).residue();
        let want = if euler == UBig::ONE { 1 } else { -1 };
        assert_eq!(jacobi_vartime(&bu(&a, 256), &pb), want);
    }
    assert_eq!(jacobi_vartime(&BoxedUint::zero_with_precision(256), &pb), 0);
    // composite modulus 15: (2/15) = 1, (5/15) = 0, (7/15) = −1
    let n = BoxedUint::from(15u64);
    assert_eq!(jacobi_vartime(&BoxedUint::from(2u64), &n), 1);
    assert_eq!(jacobi_vartime(&BoxedUint::from(5u64), &n), 0);
    assert_eq!(jacobi_vartime(&BoxedUint::from(7u64), &n), -1);
}
