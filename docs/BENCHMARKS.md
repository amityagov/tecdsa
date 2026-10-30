# Benchmarks

Measured results for the 128-bit profile (`PARAMS_128`). Desktop numbers are from an Apple M-series
laptop, release build, one thread. Phone numbers come from the example app in
[`examples/ios`](../examples/ios), which runs the server inside
the app so no network is involved.

The budgets they are compared with are in [`SPEC.md`](SPEC.md) §8.1.

## Arithmetic

`cargo bench -p tecdsa-core --bench arith`

| Operation | Time |
| --- | --- |
| Paillier enc, λ 1024 bit, mod N² (6144 bit) | 12.7 ms |
| Paillier dec (CRT) | 9.1 ms |
| `pow_ct` mod N², 448-bit exponent (E^v) | 6.3 ms |
| fixed-base ρ^λ, w=4, `pow_ct` / `pow_vartime` | 4.2 / 3.8 ms (3 MiB table per base) |
| SampleRSA 3072 bit (tough) | ~0.22 s median, 0.37 s max |
| SampleDF client 2048 bit | ~0.14 s median |

`crypto-bigint` is fast enough on its own; the variable-time `dashu-int` backend is only used as an
oracle in tests. The fixed-base tables for all four bases take 7.1 MiB, inside the 8 MiB budget.

## Zero-knowledge proofs

`cargo test -p tecdsa-core --release --lib zk -- --ignored`

| Proof | Parameters | prove | verify | Size |
| --- | --- | --- | --- | --- |
| Π_mod | N 3072 bit, 64 repetitions | 0.49 s | 0.56 s | 49,216 B |
| Π_fac | N 3072 bit, d = 2^3459+1169115 | 94 ms | 56 ms | 2,616 B |
| Π_df | N̂ 3072 bit, 128 repetitions | 89 ms | 25 ms | 5,280 B |
| Π_df* | M̂ 2048 bit, 16 repetitions, ℓ0 = 32 | ≈ 7–13 ms | ≈ 4–5 ms | 928 B |
| Π_dlog | ℓ = 128 | — | — | 49 B |
| Π_dlenc | | 16 ms | 12 ms | 692 B |
| Π_sig | | 23 ms | 28 ms | 1,054 B |

Π_df* sends two challenges (e₁, e₂) per repetition, as the paper does, which is why it is 928 B rather
than about 860 B.

## Setup and key generation (desktop)

| Step | Time | Message |
| --- | --- | --- |
| Server setup (Algorithm 4) | 1.14 s | `SetupData` 60 KB |
| Client verifies setup | 0.68 s (Π_mod 0.57 s) | — |
| Keygen S, step 1 | 0.2 ms | KgMsg1 70 B |
| Keygen C, step 2 (including M̂ generation) | 119–129 ms | KgMsg2 2,050 B |
| Keygen S, step 3 | 25 ms | KgMsg3 1,502 B |
| Keygen C, step 4 | 12 ms | — |

## Signing (desktop)

10,000 signatures, medians.

| Step | Time | Budget | Message |
| --- | --- | --- | --- |
| S1 | 0.09 ms | ≤ 2 ms | SignMsg1 ≈ 70 B |
| Client step (with Π_sig) | 33.6 ms | ≤ 60 ms | SignMsg2 1,898 B (≤ 2,048) |
| S3 (verify Π_sig + dec + ECDSA) | 38.3 ms | ≤ 40 ms | SignMsg3 ≈ 70 B |

S3 has little headroom (38 of 40 ms). Measure again on the production server CPU.

## iPhone 16 Pro

iPhone17,1, iOS 27.0, Release build, 1000 key generations and 1000 signatures in a row; thermal state
`fair` at the end.

| Operation | Result | Budget |
| --- | --- | --- |
| Setup verification + tables | 705 ms | ≤ 4 s |
| Client keygen (steps 2 + 4) | median 124 ms, p99 202 ms, max 292 ms | p99 ≤ 3 s |
| Signing, client step | median 35.6 ms, p99 37.1 ms, max 37.8 ms | ≤ 150 ms |
| Messages (measured at 0.1.3 with ℓ0 = 8; KgMsg2 is 2050 B since 0.2.0) | KgMsg2 1842 B, KgMsg3 1502 B, SignMsg1 72 B, SignMsg2 1898 B | — |

With BIP32 derivation (100 signatures on paths m/44/0/0/0/i, each verified under `X + δ·G` and rejected
under the master key): client step median 32.1 ms, p99 35.2 ms; server step S3 38.3 ms. Derivation adds no
noticeable cost.

Other phone models (iPhone 13 and older) have not been measured.

## Size

Release profile: fat LTO, `codegen-units = 1`, `panic = "abort"`, stripped. The cdylib is 0.8 MiB; an
app links only the reachable code (the `.a` is 24 MB before linking).
