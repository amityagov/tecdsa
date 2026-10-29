//! enc/dec and `pow` at 3072/6144 bits; results are in docs/BENCHMARKS.md.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use criterion::{Criterion, criterion_group, criterion_main};
use crypto_bigint::{BoxedUint, ConcatenatingMul};
use crypto_primes::{Flavor, random_prime};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tecdsa_core::{
    arith::{Modulus, SBig, fixed_base::FixedBase, sbig::SRange},
    paillier::{PaillierPk, PaillierSk},
};

fn bench(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let p: BoxedUint = random_prime(&mut rng, Flavor::Any, 1536);
    let q: BoxedUint = random_prime(&mut rng, Flavor::Any, 1536);
    let n = p.concatenating_mul(&q);
    let n2m = Modulus::new(n.concatenating_mul(&n)).unwrap();
    let rho0 = n2m.residue(&BoxedUint::from(0x1234_5678_9abc_def1u64));
    let rho = n2m
        .pow_vartime(&rho0, &SBig::from_uint(n.shl(1)))
        .unwrap()
        .retrieve();
    let pk = PaillierPk::new(n, &rho).unwrap();
    let sk = PaillierSk::new(p, q).unwrap();

    let lam = SBig::random_in(&mut rng, SRange::pm_pow2(1024));
    let m = SBig::random_in(&mut rng, SRange::pm_pow2(1024));
    let ct = pk.enc(&m, &lam, 1024).unwrap();
    let e = SBig::random_in(&mut rng, SRange::pm_pow2(448));

    c.bench_function("paillier enc (lambda 1024 bit, mod N^2 6144)", |b| {
        b.iter(|| pk.enc(&m, &lam, 1024).unwrap())
    });
    c.bench_function("paillier dec (CRT)", |b| b.iter(|| sk.dec(&ct).unwrap()));
    c.bench_function("pow_ct mod N^2, 1024-bit exp", |b| {
        b.iter(|| pk.mod_n2().pow_ct(pk.rho(), &lam, 1024).unwrap())
    });
    c.bench_function("pow_ct mod N^2, 448-bit exp (E^v)", |b| {
        b.iter(|| pk.scale(&ct, &e, 448).unwrap())
    });
    c.bench_function("pow_vartime mod N^2, 1024-bit exp", |b| {
        b.iter(|| pk.mod_n2().pow_vartime(pk.rho(), &lam).unwrap())
    });
    let n_res = Modulus::new(pk.n().clone()).unwrap();
    let base = n_res.residue(&BoxedUint::from(7u64));
    c.bench_function("pow_ct mod N (3072), 1024-bit exp", |b| {
        b.iter(|| n_res.pow_ct(&base, &lam, 1024).unwrap())
    });
    let fb = FixedBase::new(pk.mod_n2(), pk.rho(), 1024, 4);
    c.bench_function("fixed-base pow_ct rho^lambda (w=4)", |b| {
        b.iter(|| fb.pow_ct(&lam).unwrap())
    });
    c.bench_function("fixed-base pow_vartime rho^lambda (w=4)", |b| {
        b.iter(|| fb.pow_vartime(&lam).unwrap())
    });
    println!("fixed-base table size: {} KiB", fb.size_bytes() / 1024);
}

criterion_group! { name = benches; config = Criterion::default().sample_size(10); targets = bench }
criterion_main!(benches);
