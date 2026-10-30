# Notes for an external audit

The `tecdsa-core` crate implements *Two-Round 2PC ECDSA at the Cost of 1 OLE* (Adjedj et al.,
[ePrint 2025/1950](https://eprint.iacr.org/2025/1950)) on secp256k1. The design is in
[`SPEC.md`](SPEC.md). This note is a map for a reviewer, not a statement about security: **the code has
not been externally audited.**

## Where things are

| Area | Files |
| --- | --- |
| Arithmetic (signed integers, Montgomery, multiexp, fixed-base) | `arith/` |
| Paillier with `ρ^λ`, DF parameters, tough primes | `paillier.rs`, `df.rs`, `rsa/tough.rs` |
| Fiat–Shamir transcript | `transcript.rs` |
| Proofs | `zk/{dlog,df,df_star,fac,modulus,dlenc,sig}.rs` |
| Setup, keygen, signing | `setup.rs`, `keygen/`, `sign/`, `ssid.rs`, `messages.rs` |
| Child key derivation | `hd.rs` |
| Share storage | `store.rs` |
| FFI | `tecdsa-ffi/` |

Code invariants: `forbid(unsafe_code)`; `unwrap`/`expect`/`panic` are denied in the core (clippy); secrets
are `ZeroizeOnDrop`/`Zeroizing` (with the exceptions in "Known limitations"); no native dependencies;
`cargo deny` controls licenses.

## ZK checklist (spec §7): what is checked and what covers it

Common to all proofs: the whole statement goes into the transcript together with the `ssid` and the
role; the bounds on the responses are checked before the equations; group and ring elements are checked
for membership (`Z*_N`, `Z*_{N²}`, canonical point encoding, scalar < q); decoders reject trailing bytes
and non-canonical values. There are negative tests for every proof field.

| Proof | What it proves | What the verifier checks | Tests |
| --- | --- | --- | --- |
| `dlog` | knowledge of `x`, `X = g^x` | canonical encoding, the equation | honest, many_seeds, tampering, wrong_witness, decode |
| `df` | the DF parameters are well formed (knowledge of `λ`) | bounds, the equations of all repetitions | honest, tampering, wrong_witness, decode |
| `df_star` | the client's DF parameters, two checks (e1, e2) per repetition | same | honest, tampering, wrong_witness, decode |
| `fac` | `N` has no small factors | bounds on `z`, the group of `d` | boundaries, unbalanced, modified_fields |
| `modulus` | `N` is square-free with exactly two primes | Jacobi/roots, min_bits | bad_moduli, three_factor, modified_fields |
| `dlenc` | `E = enc(x2'; ·)` and `X2` agree | range, ρ and the ciphertext in `Z*` | bad_ciphertext_and_rho, tampering |
| `sig` | `S = enc(a; ρ^λ0)·E^b` with `a,b,λ0` in range | bounds on `z1,z2` (plus guard bounds `w1,w2`), 3 equations | tampering, wrong_witness_and_ranges, tables_give_same_result |

Also covered: session-binding tests (a foreign digest, `client_id`, a message of another session),
corruption of every protocol message, `robustness.rs` (mutations of the inputs of every parser and of
the protocol inputs), and `vectors/reduced.json` (a deterministic regression).

## Deviations from the paper and open questions

1. **ℓ0 = 8** is our choice; the paper does not define the parameter unambiguously (the question to the
   authors is open). Section 8.1 of the paper assumes `(r_df*, ℓ0) ≥ (16, 32)`. With `ℓ0 = 8` the per-round
   soundness is `1/ω + 2^-8` (Proposition 5.20), so a cheating subgroup of order `2^8`, `2^10`, `2^12` is
   accepted with probability about `2^-112`, `2^-123`, `2^-127`; the floor `2^-128` holds for large `ω`. The
   leak is at most `log₂ ω` bits of `x₂′` and `β`, which `ν_leak = 64` absorbs. The Π_df* mask `α` has 62 bits
   of statistical hiding (`2ℓ + ℓ0 + ν`), not 64. Moving to `ℓ0 = 32` changes the wire format of `KgMsg2`.
2. **Π_df\*:** two calls (e1, e2) per repetition, as in the paper; the spec table for KgMsg2 lists a single
   byte `e`.
3. **h, f** are derived from the random `setup_id ‖ len ‖ server_id` (this breaks the circular dependency in
   the spec); `sid` is the SHA-256 of the canonical bytes of `SetupData`.
4. **Π_sig:** guard bounds `w1`, `w2` are added (the paper checks only `z1`, `z2`); an honest prover restarts
   with probability on the order of 2^-ν.
5. **Π_fac in `verify()`** uses the standard group `d = 2^3459 + 1169115`; `verify_with` is for tests.
6. The client's DF factorization is deleted right after proving; the client's tough primes follow Alg. 3
   of the paper.
7. The 60 s keygen session timer is supplied through the `Clock` trait; the core is `no_std` and never reads
   the time itself.
8. For the 112-bit profile the parameter T of the paper is not confirmed.

## The DF part of Π_sig is required for soundness

Paillier's plaintext group `⟨1+N⟩` has the known order `N`, so the Paillier equation of Π_sig binds the
client's `u` only modulo `N`, and the curve equation binds it only modulo `q`. Only the commitment over `N̂`
(unknown order, strong RSA) forces `u` to be small as an integer (paper, Lemma 5.10, case 1). Without it a
client could send `u* = u_honest + j·q` just below `N/2`; the server recenters `dec(S)` around `N/2`, so the
validity of the final signature would depend on whether `x₂′·v` crosses a threshold: one bit of `x₂′` per
signing attempt, about `2^10` attempts at full size. An independent review reproduced this on a model of the
server's decryption (it recovered `x₂′` in 562 calls at reduced parameters); it is not reachable through the
real verifier. Regression test: `zk::sig::tests::z1_shifted_by_nq_is_rejected`. Treat the DF commitment as
part of the security model, not as an optimisation. The reference implementation reportedly has no such
part; this should be raised with its maintainers.

## Known limitations

- **Zeroization is not complete.** `PaillierSk` wipes `p`, `q` and the CRT constants, but the four `Modulus`
  fields built from `p`, `q`, `p²`, `q²` hold copies in `BoxedMontyParams`, which `crypto-bigint` 0.7 does not
  let a caller wipe (the parameters sit behind an `Arc` with no mutable access). The same applies to
  `PrimeCtx` in Π_mod, to intermediates in the tough-prime samplers, in `dec_prime` and in `ClientSign::respond`,
  and to the copies that cross the FFI (`Vec<u8>`, Swift `Data`). This is defence in depth against memory
  disclosure only; fixing it needs support upstream.
- **The HD chain code is public.** It is `SHA-256(domain ‖ X ‖ E)`, and `X`, `E` travel in the clear during
  key generation, so anyone who saw it can derive every non-hardened child public key (address
  linkability; no key leak).
- **A malicious server can choose degenerate setup values** that hurt only itself (for example a small
  subgroup). The client refuses `ρ ∈ {1, −1}`, `t`, `s₁`, `s₂ ∈ {1, −1}`, equal DF values and `N̂ = N`; the
  pinned setup hash (`ClientSetup.verify_pinned`) is the real defence.
- **Server state between rounds** is memory-only and unbounded per client; the application must cap and expire
  sessions. A persistent store would have to be single-use and keep `k₂` encrypted.
- `Instant` on Apple platforms may not count device sleep; the 60 s keygen timer should use a continuous
  clock supplied through the `Clock` trait. Not verified on a device.

## Constant time

`tests/ct.rs` (ignored; run on a quiet machine) is a dudect-style t-test of the timing of
`Modulus::pow_ct` and `FixedBase::pow_ct` between two classes of exponents (a small value and a full-width
value with a random sign): `|t| ≈ 1` on Apple M. Caveats: the width (number of limbs) of the exponent is
treated as public — the first run of the test showed that the time differs with different widths; every
protocol exponent arrives at a fixed width, but a reviewer should double-check this. Not checked: `dec`
(CRT), scalar multiplication (`k256`), `invert`, the search in `Modulus::new`. Server operations on public
data (`pow_vartime`, multiexp) run in variable time on purpose.

## Fuzzing

`fuzz/` has three libFuzzer targets, input parsing only: `messages` (all messages, points, scalars),
`setup_and_secrets` (`SetupData::from_bytes`, share import), `zk_decoders` (`dlog`, `df_star`, `dlenc`,
`sig`). The `fuzz/` crate is outside the workspace and builds on nightly.

Install and run (from the repository root):

```sh
cargo install cargo-fuzz
rustup toolchain install nightly          # if missing
cd fuzz
cargo +nightly fuzz list                  # messages, setup_and_secrets, zk_decoders
cargo +nightly fuzz run messages          # until Ctrl-C
cargo +nightly fuzz run messages -- -max_total_time=86400    # 24 hours
cargo +nightly fuzz run setup_and_secrets -- -max_total_time=86400 -max_len=70000
cargo +nightly fuzz run zk_decoders -- -max_total_time=86400 -max_len=70000
```

The three targets are convenient to run in parallel (one per core; `-jobs=N -workers=N` runs several
processes per target). The corpus lives in `fuzz/corpus/<target>/` (not committed), crashes in
`fuzz/artifacts/<target>/`. Reproduce a crash with `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`,
minimize with `cargo +nightly fuzz tmin <target> <file>`, coverage with `cargo +nightly fuzz coverage <target>`.
A good starting corpus is real protocol messages: they can be saved from the tests (`robustness.rs`) into
`fuzz/corpus/messages/`. The release criterion is 24 hours per target without crashes or timeouts.

Status: **24-hour runs with coverage have not been done.** The targets were run for 40 s each without
coverage instrumentation (nearly random input and a weak check); there were no crashes.
