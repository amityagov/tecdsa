//! dudect-style timing checks (Welch t-test between two input classes) for the secret-exponent
//! exponentiations. Statistical and noise-sensitive, so ignored by default:
//! `cargo test --release --test ct -- --ignored --nocapture` on a quiet machine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::time::Instant;

use crypto_bigint::{BoxedUint, ConcatenatingMul, Resize};
use crypto_primes::{Flavor, random_prime};
use rand_chacha::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};
use tecdsa_core::arith::{Modulus, SBig, fixed_base::FixedBase, sbig::SRange};

const BITS: u32 = 256;

fn class_width() -> u32 {
    SBig::random_in(&mut ChaCha8Rng::seed_from_u64(0), SRange::pm_pow2(BITS))
        .mag()
        .bits_precision()
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let stat = |v: &[f64]| {
        let n = v.len() as f64;
        let m = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (n - 1.0);
        (m, var / n)
    };
    let ((ma, va), (mb, vb)) = (stat(a), stat(b));
    (ma - mb) / (va + vb).sqrt()
}

/// Class 0: tiny positive exponents (low Hamming weight); class 1: full-width, random sign.
fn class_exp(rng: &mut ChaCha8Rng, class: bool) -> SBig {
    if class {
        SBig::random_in(rng, SRange::pm_pow2(BITS))
    } else {
        // same limb width as class 1: the width is public, only the value must not matter
        let small = BoxedUint::from(u64::from(rng.next_u32() % 4) + 1);
        SBig::from_uint(small.resize(class_width()))
    }
}

fn measure(name: &str, mut op: impl FnMut(&SBig)) {
    let mut rng = ChaCha8Rng::seed_from_u64(5);
    let n = 3000;
    let (mut t0, mut t1) = (Vec::new(), Vec::new());
    for i in 0..(2 * n + 200) {
        let class = rng.next_u32() & 1 == 1;
        let e = class_exp(&mut rng, class);
        let t = Instant::now();
        op(&e);
        let d = t.elapsed().as_nanos() as f64;
        if i < 200 {
            continue; // warm-up
        }
        if class { t1.push(d) } else { t0.push(d) }
    }
    // crop the slowest 10% of each class (scheduler noise)
    let crop = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v.truncate(v.len() * 9 / 10);
    };
    crop(&mut t0);
    crop(&mut t1);
    let t = welch_t(&t0, &t1);
    println!(
        "{name}: |t| = {:.2} (n = {} / {})",
        t.abs(),
        t0.len(),
        t1.len()
    );
    assert!(
        t.abs() < 10.0,
        "{name}: timing depends on the exponent (t = {t})"
    );
}

fn modulus(rng: &mut ChaCha8Rng) -> Modulus {
    let p: BoxedUint = random_prime(rng, Flavor::Any, 512);
    let q: BoxedUint = random_prime(rng, Flavor::Any, 512);
    Modulus::new(p.concatenating_mul(&q)).unwrap()
}

#[test]
#[ignore = "statistical timing test; run on a quiet machine"]
fn pow_ct_does_not_leak_exponent() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let m = modulus(&mut rng);
    let base = m.residue(&BoxedUint::from(0xdead_beef_1234_5677u64));
    measure("Modulus::pow_ct", |e| {
        std::hint::black_box(m.pow_ct(&base, e, BITS).unwrap());
    });
}

#[test]
#[ignore = "statistical timing test; run on a quiet machine"]
fn fixed_base_pow_ct_does_not_leak_exponent() {
    let mut rng = ChaCha8Rng::seed_from_u64(2);
    let m = modulus(&mut rng);
    let base = m.residue(&BoxedUint::from(0xdead_beef_1234_5677u64));
    let table = FixedBase::new(&m, &base, BITS, 4);
    measure("FixedBase::pow_ct", |e| {
        std::hint::black_box(table.pow_ct(e).unwrap());
    });
}
