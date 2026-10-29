# Design specification

Two-party ECDSA on secp256k1 in pure Rust, after Adjedj, Blokh, Couteau, Galansky, Joux and
Makriyannis, *Two-Round 2PC ECDSA at the Cost of 1 OLE* ([ePrint 2025/1950](https://eprint.iacr.org/2025/1950),
version of 6 March 2026). This document records what `tecdsa-1ole` implements, the parameters it
uses and the encodings it puts on the wire. Source comments refer to its sections as `spec §N`.

Where this document and the paper disagree, the paper (sections 4–5 and 8.1) is the source of truth
for formulas and checks. The overview in the paper's section 2 simplifies the roles: there `P1` owns the
Paillier key, in section 4 the server does. This implementation follows section 4.

## 1. Goal and scope

A signature takes two rounds, about 2 KB of traffic and, on the paper's reference hardware, about
50 ms of computation.

**Roles.** One server `S` serves many clients (a star topology). `S` holds the Paillier key and the
Damgård–Fujisaki (DF) parameters. The client `C` is a mobile app (iOS) or a native service.

**In scope:**

- Server setup (Algorithm 4).
- Distributed key generation (Protocol 2).
- Signing (Protocol 3).
- The seven zero-knowledge proofs of section 7.
- The tough-RSA modulus generator (Algorithm 3).
- Message serialization, tests, benchmarks, iOS build.
- BIP32 non-hardened derivation of child public keys (`tecdsa-core/src/hd.rs`).

**Out of scope:**

- Transport: network, push notifications, QR codes. The crate takes and returns bytes.
- Secret storage: Keychain, Secure Enclave, HSM. It is a trait the application implements.
- Key refresh and rotation, more than two parties, hardened derivation.
- An external security audit. It is required before production use and is not part of this repository.

## 2. Hard constraints

Every dependency must be pure Rust, licensed MIT, Apache-2.0 or BSD, and build for iOS without
external toolchains.

1. **No native dependencies.** `rug`, `gmp-mpfr-sys`, `openssl`, `ring` and any `-sys` crate with C or
   assembly are banned. `cargo build --target aarch64-apple-ios` must work without `cc`, `cmake` or
   `autotools`.
2. **No LGPL or GPL.** `rug`, `malachite` (LGPL-3.0) and everything derived from GMP are banned.
   Allowed: MIT, Apache-2.0, BSD-2/3, ISC, Unicode-DFS, Zlib. `cargo deny check licenses` enforces a
   strict allow-list in CI. The one exception is MPL-2.0 for `uniffi` and its runtime, used only by
   `tecdsa-ffi`.
3. **No `unsafe` in our code.** `#![forbid(unsafe_code)]`. Dependencies may use `unsafe` only if they
   are vetted RustCrypto crates.
4. **`no_std` + `alloc` for the core.** The math and the protocols do not use `std`. `std` is needed only
   for the `getrandom`/`OsRng` feature and the FFI layer.
5. **Targets:**
   - `aarch64-apple-ios` (devices);
   - `aarch64-apple-ios-sim` and `x86_64-apple-ios` (simulators);
   - `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` (server and CI).
6. **MSRV is Rust 1.85, edition 2024**, as `crypto-bigint` 0.7 requires.
7. **One RustCrypto version graph.** `k256`, `elliptic-curve`, `crypto-bigint`, `crypto-primes` and
   `rand_core` must resolve to compatible versions without duplicates; CI checks `cargo tree -d`.

## 3. Libraries

The base is the RustCrypto stack: `k256` for the curve, `crypto-bigint` for big numbers and
`crypto-primes` for primes. All three are pure Rust under MIT/Apache-2.0, support `no_std` and are
constant-time by default. Versions are pinned in `Cargo.lock`.

**Design decisions:**

- **Server on Rust.** The server may use the variable-time `dashu-int` backend for operations on public
  data: proof verification and modulus generation. Decryption and anything involving φ(N) stays on
  `crypto-bigint`.
- **Swift bridge: `uniffi`.** `tecdsa-ffi` is built on `uniffi`; the XCFramework is produced with its
  tooling.

| Task | Crate | License | What is used | Notes |
| --- | --- | --- | --- | --- |
| secp256k1 | `k256` (features `arithmetic`, `ecdsa`, `hash2curve`, `serde`) | MIT/Apache-2.0 | `ProjectivePoint`, `Scalar`, ECDSA verification, hash-to-curve for h, f | 𝒳(R): `AffineCoordinates::x()` + `Reduce<U256>` |
| 3072/6144-bit numbers | `crypto-bigint` 0.7 (features `alloc`, `rand_core`, `zeroize`) | MIT/Apache-2.0 | `BoxedUint`, `BoxedMontyForm`, `BoxedMontyParams`, `JacobiSymbol`, `pow_vartime` | main backend |
| Primes | `crypto-primes` | MIT/Apache-2.0 | `random_prime`, `is_prime` (Miller–Rabin + Lucas) | tough primes are built on top |
| Hash / Fiat–Shamir | `sha2` (SHA-256/512) | MIT/Apache-2.0 | transcript, random oracles, challenge derivation | own transcript with domain separation |
| Randomness | `rand_core` + `rand_chacha` + `getrandom` | MIT/Apache-2.0 | `OsRng`, deterministic RNG in tests | on iOS `getrandom` uses the system entropy source |
| Wiping, comparison | `zeroize`, `subtle` | Apache-2.0 / BSD-3 | `Zeroizing`, `ConstantTimeEq` | every secret type is `ZeroizeOnDrop` |
| Serialization | `serde` + `postcard` | MIT/Apache-2.0 | compact binary message format | canonical field order, version in the header |
| Errors | `thiserror` 2.x | MIT/Apache-2.0 | the `Error` enum | works in `no_std` |
| Swift bridge | `uniffi` | MPL-2.0 (exception) | bindings, XCFramework | `tecdsa-ffi` only |
| Optional fast variable-time arithmetic | `dashu-int` | MIT/Apache-2.0 | signed `IBig`/`UBig` with fast modpow | public data only; also the oracle in property tests |

**Rejected:**

- `rug`, `gmp`: native build and LGPL.
- `malachite`: LGPL-3.0.
- `num-bigint`: no Montgomery form, not constant-time, noticeably slower at 3072 bits.
- `openssl`, `ring`: native code.

**Signed numbers.** The protocol works with ranges ±2ⁿ and negative responses z. A dedicated type
`SBig { neg: Choice, mag: BoxedUint }` provides constant-time operations. A negative exponent is an
inversion of the base followed by a power of |e|.

**Two arithmetic implementations.**

- `ct` (default): for every secret exponent and for all client code.
- `vartime`: only for operations on public data, such as proof verification and `pow` with a public
  exponent. The choice is made per call (`pow_ct` / `pow_vartime`), not by a global feature.

## 4. Crate architecture

A workspace of two crates. `tecdsa-core` is `no_std` + `alloc` and holds all math and protocols,
without I/O. `tecdsa-ffi` is a thin layer for Swift and the server. The hot path is `sign` and Π_sig;
most of the optimization budget goes there.

Dependencies point strictly downward: protocols never touch `BoxedUint` directly, only through
`arith` and the primitives.

```
tecdsa-core/src/
  lib.rs            // public API, Error, PROTOCOL_VERSION
  params.rs         // Params128, Params112 (section 5)
  arith/
    sbig.rs         // signed number over BoxedUint
    monty.rs        // pow_ct / pow_vartime, inversion, Jacobi symbol
    multiexp.rs     // Straus/Shamir for 2-4 bases
    fixed_base.rs   // comb tables for ρ, t, s1, s2
  curve.rs          // 𝒳(R), hash-to-curve for h, f, point encoding
  transcript.rs     // SHA-256, domain separation, RO, challenges ±2^ℓ
  rsa/tough.rs      // Algorithm 3: SampleRSA / SampleDF
  paillier.rs       // enc with a small exponent, CRT decryption
  df.rs             // Damgård–Fujisaki commitments
  zk/{modulus,fac,df,df_star,dlog,dlenc,sig}.rs
  setup.rs          // Algorithm 4: generation (S) and verification (C)
  keygen/{server,client}.rs   // Protocol 2
  sign/{server,client}.rs     // Protocol 3
  hd.rs             // BIP32 non-hardened derivation
  messages.rs       // wire formats, version
  store.rs          // SecretStore trait
tecdsa-ffi/         // UniFFI bindings, XCFramework
```

Every round is its own state type, consumed by value by the method that handles the next message.
Reusing the nonces k₁/k₂ or answering the same round twice therefore does not compile.

## 5. Security parameters

The main profile is 128 bits; the 112-bit profile exists only for benchmarks. All parameters are
collected in `struct Params` and checked by `const` assertions. There are no magic numbers in the code.

| Parameter | Meaning | 128 bit | 112 bit |
| --- | --- | --- | --- |
| κ | curve order, bits | 256 | 256 |
| ℓ | soundness, bits | 128 | 112 |
| ν | statistical noise, bits | 64 | 64 |
| ε = ℓ + ν | slack | 192 | 176 |
| n\_rsa | Paillier and DF modulus of the server, bits | 3072 | 2048 |
| n (client) | ephemeral DF modulus M̂ of the client, bits | 2048 | 2048 |
| ν\_leak | noise against subgroup leakage | 64 | 64 |
| r\_mod | Π\_mod repetitions (ℓ/2) | 64 | 56 |
| r\_df | Π\_df repetitions | 128 | 112 |
| r\_df\* / ℓ₀ | Π\_df\* repetitions / challenge size | 16 / see open question | 16 / see open question |
| n\_x = κ + ν\_leak | range of x₂′ | 320 | 320 |
| n\_λ = 2ℓ + ν\_leak | range of β | 320 | 288 |
| n\_b = κ + ℓ + ν | range of v | 448 | 432 |
| n\_a = n\_x + ε + n\_b + ν | range of u | 1024 | 992 |
| n\_λ0 = n\_λ + ε + n\_b + ν | range of λ₀ | 1024 | 960 |
| n\_tρ | randomness of the DF commitment | 1408 | 1344 |
| T = n\_rsa / 4ℓ | small primes in (p−1)/2 | 6 × 256 bit | ⌈2048/448⌉ = 5 × 224 bit (open: 1120 > 1024) |
| d (Π\_fac) | public strong prime | 2³⁴⁵⁹ + 1169115 | same |

**Open question on ℓ₀.** In section 8.1 of the paper ℓ₀ = 32, while in sections 6.2–6.3 ℓ₀ = ⌈ℓ / r\_df\*⌉ = 8.
The value determines the size of Π\_df\* and the soundness loss (guessing ω < 2^ℓ₀). The default is
ℓ₀ = 8 with r\_df\* = 16, which gives 128 bits of soundness and matches the proof. The question to the
authors is still open.

**The constant d.** It is hard-coded as bytes. A test checks that d and (d−1)/2 are prime. The
generators g, h of QR\_d are derived deterministically from `aux` through the transcript.

## 6. Protocols

There are three phases: setup once per server, keygen once per client wallet, sign once per
transaction. The identifiers FR-x are used in tests and in code comments. Any failed check produces a
typed error and destroys the session state.

### 6.1 Server setup (Algorithm 4)

- **FR-S1.** The Paillier modulus N = p₁p₂ comes from `SampleRSA`. Requirements: tough structure,
  p₁ ≡ 3 and p₂ ≡ 7 (mod 8), gcd(p₁−1, p₂−1) = 2.
- **FR-S2.** Proofs Π\_mod (r\_mod repetitions) and Π\_fac for N.
- **FR-S3.** ρ₀ ← Z\*\_N, ρ = ρ₀^{2N} mod N².
- **FR-S4.** The DF tuple (N̂, t, s₁, s₂) from `SampleDF`, λ₁, λ₂ ← \[2^{2ℓ}\]. Proof Π\_df (r\_df
  repetitions). After proving, the factorization of N̂ and the λᵢ are destroyed.
- **FR-S5.** h, f ∈ G are derived by hash-to-curve from `aux = (sid, S)`. The derivation is deterministic
  and reproducible by the client.
- **FR-S6.** Output: `SetupData` (about 60 KB) and the secret `PaillierSk { p, q, φ(N) }` with precomputed
  CRT data, `ZeroizeOnDrop`.
- **FR-S7.** The client verifies:
  - N, N̂ ≥ 2^{n\_rsa−1};
  - ρ₀ ∈ Z\*\_N and ρ = ρ₀^{2N};
  - t, s₁, s₂ ∈ Z\*\_N̂;
  - h and f equal the recomputed values;
  - the three proofs are valid.

  The result is cached by the SHA-256 of `SetupData`, so the check (about 0.5 s) is not repeated for
  every keygen.
- **FR-S8.** The authenticity of `SetupData` (a signature by a long-term server key, or pinning of the
  hash in the app) is the application's job. The crate exposes the hash for pinning.

### 6.2 Key generation (Protocol 2)

Four messages; ssid = (sid, keygen, C, unique session nonce).

1. **S → C:** S picks x₂′ ← ±2^{n\_x}, X₂ = g^{x₂′} and sends the commitment B = RO(ssid, S, X₂).
2. **C → S:** C picks x₁ ← F\_q and an ephemeral DF tuple (M̂, v, u₁, u₂) from `SampleDF` at 2048 bits.
   It sends X₁ = g^{x₁}, ψ\_df\* and ψ\_dlog. A 60-second timer starts here.
3. **S → C:** S verifies ψ\_df\* and ψ\_dlog, picks β ← ±2^{n\_λ} and computes E = enc\_N(x₂′; ρ^β). It
   sends X₂, E and ψ\_dlenc.
4. **C:** verifies E ∈ Z\*\_{N²}, B = RO(ssid, S, X₂), ψ\_dlenc and that the timer has not expired. Then it
   destroys the factorization of M̂.

Output: X = X₁·X₂ and E on both sides. S stores x₂ = x₂′ mod q, C stores x₁. The label in the RO is
always the identifier of S (the paper has a typo with C in Game2).

### 6.3 Signing (Protocol 3)

The crate signs a 32-byte digest m. Hashing the transaction (SHA-256d for Bitcoin, Keccak-256 for
Ethereum) is done by the caller. ssid = (sid, sign, m, C, X, E, unique session id).

1. **S → C** (about 66 bytes): k₂ ← F\_q, R₂ = g^{k₂}, Y = X₁^{k₂}.
2. **C → S** (about 1.9 KB):
   - check R₂ ≠ 1 and R₂^{x₁} = Y;
   - k₁ ← F\_q, λ₀ ← ±2^{n\_λ0}, μ ← ±⌊2^{n\_a}/q⌋, μ′ ← ±⌊2^{n\_b}/q⌋;
   - R₁ = g^{k₁}, R = R₂^{k₁}, e = RO(X, R₁, R, m), r = 𝒳((R₂·g^e)^{k₁});
   - u = \[k₁⁻¹(m + r·x₁)\]\_q + μq, v = \[k₁⁻¹r\]\_q + μ′q;
   - S = enc\_N(u; ρ^{λ₀})·E^v mod N², ψ\_sig;
   - send R₁, R, S, ψ\_sig.
3. **S** (final):
   - check R₁ ≠ 1, S ∈ Z\*\_{N²}, R = R₁^{k₂}, ψ\_sig;
   - r = 𝒳(R₁^{k₂+e}), σ = dec(S)·(k₂ + e)⁻¹ mod q;
   - verify (r, σ) with plain ECDSA verification against X and m.

**Additional signing requirements:**

- **FR-G1. Low-s normalization** (BIP-62, EIP-2): if σ > q/2, use q − σ.
- **FR-G2. Recovery id** for Ethereum is computed from the parity of the y coordinate of R₁^{k₂+e} and
  the overflow flag x ≥ q. Normalizing s flips the parity bit.
- **FR-G3. Delivering the signature to the client.** The server obtains the signature. An optional third
  message S → C with (r, σ, recid) is verified locally by the client.
- **FR-G4. Nonce.** k₁ and k₂ are hedged: k = H(OsRng ‖ secret ‖ ssid) mod q. The round state is consumed
  by value, so a second answer is impossible.
- **FR-G5. Concurrency.** The server runs any number of parallel sessions on one key. States are
  independent; only the read-only `SetupData` is shared.

```rust
// sketch of the public API (tecdsa-core)
pub fn server_setup(rng, params) -> (SetupData, ServerSetupSecret);
pub fn client_verify_setup(setup: &SetupData, params) -> Result<VerifiedSetup>;

pub struct ServerKeygen0; impl ServerKeygen0 { fn start(..) -> (Self::Next, KgMsg1) }
pub struct ClientKeygen0; impl ClientKeygen0 { fn on_msg1(self, KgMsg1) -> Result<(ClientKeygen1, KgMsg2)> }
// ... -> ServerKeyShare { x2, X, E } / ClientKeyShare { x1, X, E }

pub struct ServerSign0; impl ServerSign0 { fn start(share, digest, ssid) -> (ServerSign1, SignMsg1) }
pub struct ClientSign;  impl ClientSign  { fn respond(share, digest, ssid, SignMsg1) -> Result<SignMsg2> }
impl ServerSign1 { fn finish(self, SignMsg2) -> Result<Signature /* r, s, recid */> }
```

## 7. Zero-knowledge proofs

All seven proofs are Σ-protocols from section 5 of the paper, made non-interactive by Fiat–Shamir.
Each lives in its own module with a `prove` / `verify` pair and the mandatory checks listed below.
Skipping a range or membership check is a critical defect: key-extraction attacks are built on such
omissions (MYG23).

| Proof | Statement | Where | Challenge × repetitions | Mandatory verifier checks |
| --- | --- | --- | --- | --- |
| Π\_mod (Protocol 5) | N is Paillier–Blum, gcd(N, φ(N)) = 1 | setup | y ← Z\*\_N × r\_mod | N ≡ 1 mod 4; N composite; (2/N) = −1; x⁴ = (−1)^a·w^b·y; y = z^N |
| Π\_fac (Protocol 4) | the factors of N are not smaller than √N / 2^ℓ | setup | ±2^ℓ × 1 | z₁, z₂ ∈ ±2^{n/2+ℓ+ν}; three equations mod d; d is the strong prime from the parameters |
| Π\_df (Protocol 8) | s₁, s₂ ∈ ⟨t⟩, \|λᵢ\| < 2^{2ℓ+ν} | setup | {0,1}² × r\_df | t ∈ Z\*\_N̂; z ∈ ±2^{2ℓ+ν}; t^z = A·s₁^{e₁}s₂^{e₂} |
| Π\_df\* (Protocol 9) | relaxed version: allows a subgroup of order < 2^{ℓ₀} | keygen (C) | \[0, 2^{ℓ₀}) × r\_df\* | t ∈ Z\*\_M̂; t^z = A·s₁^{e₁}s₂^{e₂}; size of M̂ |
| Π\_dlog (5.13) | knowledge of x₁ for X₁ | keygen (C) | ±2^ℓ × 1 | X^e·A = g^z; X₁ ≠ 1 |
| Π\_dlenc (Protocol 7) | E encrypts dlog(X₂) with a small randomizer | keygen (S) | ±2^ℓ × 1 | z₁ ∈ ±2^{n\_x+ε}, z₂ ∈ ±2^{n\_λ+ε}; equations in G, mod M̂, mod N²; E, D ∈ Z\*\_{N²} |
| Π\_sig (Protocol 6) | S = enc(u; ρ^{λ₀})·E^v with small u, v; commitment Ũ = g^u h^v f^γ | sign (C) | ±2^ℓ × 1 | z₁ ∈ ±2^{n\_a+ε}, z₂ ∈ ±2^{n\_b+ε}; equations in G, mod N̂, mod N²; S, D ∈ Z\*\_{N²} |

**General requirements:**

- **ZK-1. Transcript.** The Fiat–Shamir hash covers the protocol label and version, the ssid, all
  parameters (N, N̂, M̂, ρ, t, s₁, s₂, h, f), the statement and the prover's first message. The encoding
  is unambiguous: a length plus the value, fixed width for group elements.
- **ZK-2. Challenges.** Derived from SHA-256 with a counter, uniform in ±2^ℓ or {0,1}^k without bias
  (rejection sampling).
- **ZK-3. Secrets.** The masks α, β, γ′, μ′, λ′ are uniform in the stated ranges. Exponentiation with a
  secret exponent uses only `pow_ct`.
- **ZK-4. Verification.** Uses `pow_vartime` and multi-exponentiation. Cheap range and membership checks
  run before expensive exponentiations, with early exit.
- **ZK-5. Π\_mod.** Implemented after section 5.2 of the paper and cross-checked against the Π\_mod of
  CGGMP21 (Dfns `paillier-zk`), which already exists in Rust.
- **ZK-6. Correctness and rejection tests.** For every proof: an honest prover passes; changing any
  element breaks verification; responses at the range boundary ± 1 are checked explicitly.

## 8. Non-functional requirements

A signature must fit in two rounds, about 2 KB of traffic and at most 150 ms per client step on an
iPhone. The requirements below deliver that without losing security.

### 8.1 Performance

The paper's reference numbers (C/OpenSSL, i7-1365U, one thread) are 29 ms for the client step and
19 ms for the server step of a signature. Pure Rust on `crypto-bigint` is expected to be slower, so the
budgets below leave headroom. Measured results are in [`BENCHMARKS.md`](BENCHMARKS.md).

| Operation | Linux x86-64, 1 thread | iPhone 13+ (A15) | Traffic |
| --- | --- | --- | --- |
| Sign, step S1 | ≤ 2 ms | — | ≤ 0.07 KB |
| Sign, step C | ≤ 60 ms | ≤ 150 ms | ≤ 2.0 KB |
| Sign, step S3 | ≤ 40 ms | — | — |
| Keygen, step C (including M̂ generation at 2048 bits) | ≤ 300 ms (p99) | ≤ 3 s (p99) | ≤ 6 KB |
| Keygen, steps S | ≤ 30 ms | — | ≤ 3 KB |
| Setup verification by the client | ≤ 1 s | ≤ 4 s | about 60 KB, once |
| Server setup | ≤ 3 s | — | — |

**Required optimizations:**

- **Small exponents** wherever the paper specifies them: the randomizer is ρ^β, not ρ^N.
- **(1 + N)^m = 1 + mN mod N²** without exponentiation.
- **CRT decryption** over p² and q².
- **Fixed-base comb tables** for ρ, t, s₁, s₂, built once per `SetupData`. Cached in memory on the client;
  the tables stay within 8 MB.
- **Multi-exponentiation** (Straus/Shamir) in verification.
- **`BoxedMontyParams`** are created once per modulus and reused.

### 8.2 Implementation security

- **Constant time:** every operation on x₁, x₂, k₁, k₂, β, λ₀, μ, μ′, the ZK masks and φ(N). Checked with a
  dudect-style tool on the critical functions.
- **Secrets:** every secret type is `ZeroizeOnDrop`, without `Clone`; `Debug` prints `***`. Secrets are
  serialized only through an explicit `export_secret()` for `SecretStore`.
- **No panics** in `tecdsa-core`: `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`.
  Every error is returned through `Result`.
- **Input validation:** every deserialized point is checked to be on the curve and not the identity,
  numbers are range-checked, elements of Z\*\_N² are coprime to N.
- **Logs** contain no secrets or intermediate values.

### 8.3 Serialization and versioning

- `postcard` format with a header: protocol version (u16), parameter-set id (128/112), message type.
- Big numbers are big-endian of fixed length per modulus; points are 33 bytes, compressed SEC1.
- Deserializers are fuzzed (`cargo-fuzz`, 24 hours without a crash before a release).

### 8.4 iOS build

- Targets `aarch64-apple-ios` and `aarch64-apple-ios-sim`, built into an `XCFramework` by a script in the
  repository. `rustup target add` is enough; no Xcode dependency except the linker.
- Release profile: `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` for FFI.
- The static library stays within 3 MB after strip.
- `getrandom` on iOS goes through the system entropy source; checked by a test on the simulator.
- FFI returns error codes and byte buffers. Storing x₁ is the application's concern (Keychain with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) through the `SecretStore` trait.

## 9. Testing and risks

### 9.1 Testing

- **Unit.** `SBig`/Monty arithmetic is compared with `dashu-int` as an oracle through property tests
  (`proptest`), at least 10⁵ cases per operation.
- **ZK.** Positive and negative tests for every proof (ZK-6), including tampering with every message field.
- **End to end.** 10⁴ signatures on random digests. Each passes
  `k256::ecdsa::VerifyingKey::verify_prehash`, and for Ethereum `ecrecover`.
- **Test vectors.** A deterministic RNG (ChaCha20 with a fixed seed) produces `vectors/*.json` for setup,
  keygen and sign. They pin the wire format between versions.
- **Malicious party.** A separate suite: a client with a wrong x₁ in the OLE, a server with an E of the
  wrong structure, a replayed round message, parallel sessions with one ssid. The expected result is an
  error, with no leak and no valid signature.
- **Platforms.** CI on Linux and macOS; tests on the iOS simulator; `criterion` benchmarks on a device
  through the example app.
- **Static checks.** `cargo deny` (licenses, advisories), `cargo audit`, `clippy -D warnings`, `cargo tree -d`.

### 9.2 Risks

| Risk | Consequence | Mitigation |
| --- | --- | --- |
| `crypto-bigint` is 2–4 times slower than GMP at 6144 bits | the 150 ms iPhone budget is missed | fixed-base tables, small exponents; `dashu-int` on the server for verification; measured early |
| Non-standard assumptions (GGM, SEI, tough RSA, doubly-enhanced unforgeability) | security is weaker than expected | audit, follow new publications; parameters with headroom |
| Ambiguities in the paper (ℓ₀, party roles, RO labels, T for 112 bits) | incompatibility or weakening | questions to the authors; implementation follows sections 4–5 |
| A missed check in a ZK proof | key extraction (the MYG23 attack class) | the checklist of section 7, negative tests for every field |
| Timing leak on the client | recovery of x₁ or k₁ | only `pow_ct` for secrets, constant-time tests |
| Substituted `SetupData` | a malicious server with a faulty modulus | pin the setup hash in the app (FR-S8) |
| License drift of dependencies | LGPL or MPL ends up in the build | `cargo deny` with an allow-list in CI |

## 10. Transcript and wire format

What is hashed is not the wire message but the canonical encoding of values in the transcript, so the
network format can change without touching the proofs. Proofs travel in compact form (challenge e +
responses z); only then does a signature fit in about 1.9 KB.

### 10.1 Transcript

The state is an incremental SHA-256. All labels are ASCII strings with the prefix `tecdsa-1ole/v1/`.

- **Creation:** `Transcript::new(domain)`, then `append("params", params_id)`. Example domains: `zk/sig`,
  `zk/dlenc`, `ro/kg-commit`, `ro/sign-nonce`.
- **append(label, bytes):** the hash receives `0x01 ‖ u32be(len(label)) ‖ label ‖ u64be(len(bytes)) ‖ bytes`.
- **challenge(label):** a copy of the state receives `0x02 ‖ u32be(len(label)) ‖ label`. The digest is the
  seed. Expansion is SHA-256(seed ‖ u32be(ctr)) for ctr = 0, 1, 2…, as many bytes as needed.
- **Order in every proof:** ssid → all public parameters by name (N, ρ, N̂, t, s₁, s₂, h, f, M̂, v, u₁, u₂,
  whatever is used) → the statement (E, S, X, P̃, Ũ…) → the prover's first message → challenge.

### 10.2 Canonical value encoding

| Type | Encoding | Check on decoding |
| --- | --- | --- |
| Scalar F\_q | 32 bytes big-endian | value < q |
| Point G | 33 bytes, compressed SEC1 | on the curve; not the identity |
| Element of Z\_M (M = N, N², N̂, M̂, d) | big-endian, fixed length ⌈bits(M)/8⌉ | value < M; for Z\*\_M, gcd(·, M) = 1 |
| Modulus (N, N̂, M̂) | big-endian, fixed length from the parameters | exact bit length, odd |
| Signed z ∈ ±2^n | 1 sign byte (0x00 = "+", 0x01 = "−") + magnitude, ⌈(n−1)/8⌉ bytes BE | \|z\| ≤ 2^{n−1}; zero only with sign 0x00 |
| Integers | u16/u32/u64 big-endian | — |
| Strings and ids | u32be(len) ‖ bytes | len ≤ 256 |

**About ±.** In the paper ±L is an interval of size L: {−L/2+1, …, L/2}. So ±2^n means |z| ≤ 2^{n−1}, not
2^n. Every range is read this way: mask sampling, challenges and the verifier's range checks. One helper,
`SRange::pm_pow2(n)`, is used everywhere.

### 10.3 Challenge derivation

| What | How |
| --- | --- |
| e ∈ ±2^ℓ | take ℓ bits u from the stream, e = u − 2^{ℓ−1} + 1 (unbiased) |
| e ∈ {0,1} × r (Π\_df) | r consecutive bits from the stream |
| e ∈ \[0, 2^{ℓ₀}) × r (Π\_df\*) | r chunks of ℓ₀ bits |
| Scalar F\_q (signature RO) | 64 bytes, reduced mod q (`Reduce<U512>`), bias about 2^{−256} |
| y ∈ Z\*\_N (Π\_mod, r\_mod of them) | bits(N)+128 bits, reduced mod N; if gcd(y, N) ≠ 1, the next ctr |
| Commitment B (keygen) | first 32 bytes of the seed, label `ro/kg-commit` |
| g, h ∈ QR\_d (Π\_fac) | value mod d from the stream with label `zk/fac/gen`, then squared mod d; reject 0 and 1 |
| h, f ∈ G | `k256` hash2curve, DST `tecdsa-1ole/v1/h2c/secp256k1_XMD:SHA-256_SSWU_RO_`, messages `"h" ‖ sid` and `"f" ‖ sid` |

### 10.4 ssid

The ssid is encoded as one record and is always the first item of every transcript and RO.

- `sid` = SHA-256(canonical bytes of `SetupData`); it doubles as the hash for pinning (FR-S8).
- `server_id`, `client_id`: strings of up to 256 bytes, set by the application.
- **keygen:** `kind = 0x01`, `kg_nonce` is 32 random bytes from the server in KgMsg1.
- **sign:** `kind = 0x02`, `key_id` = SHA-256(X ‖ E), digest m, R₂. R₂ is fresh in every session and serves as
  its unique id; no separate nonce is needed.

### 10.5 Messages

Envelope: `u16 version (=1) ‖ u8 params_id ‖ u8 msg_type ‖ body`. The body is a `postcard` structure; all
big numbers are byte arrays of the fixed length from 10.2, and any other length is an error. The maximum
message size for its type is checked before parsing.

Proofs travel in the compact form (e, z…). The verifier reconstructs the first message (for example
A = g^{z}·X^{−e}), recomputes the challenge and compares it with e. All range checks on z remain.
Auxiliary statement commitments (P̃, Ũ) are sent explicitly.

Sizes for the 128-bit profile (N 3072, N² 6144, N̂ 3072, M̂ 2048 bits):

| Message | Direction | Fields | Size, bytes |
| --- | --- | --- | --- |
| KgMsg1 | S → C | kg\_nonce 32, B 32 | ≈ 68 |
| KgMsg2 | C → S | X₁ 33; M̂, v, u₁, u₂ 256 each; ψ\_df\*: 16 × (e 1 + z ≈ 42); ψ\_dlog: e 17 + z 32 | ≈ 1 800 |
| KgMsg3 | S → C | X₂ 33; E 768; ψ\_dlenc: P̃ 256, e 17, z₁ 65, z₂ 65, z₃ 289 | ≈ 1 500 |
| SignMsg1 | S → C | R₂ 33, Y 33 | ≈ 70 |
| SignMsg2 | C → S | R₁ 33, R 33, S 768; ψ\_sig: P̃ 384, Ũ 33, e 17, z₁ 153, z₂ 81, w₀ 32, w₁ 201, w₂ 153 | ≈ 1 890 |
| SignMsg3 (optional) | S → C | r 32, s 32, recid 1 | ≈ 70 |
| SetupData | S → C, once | N, ρ₀, ρ, N̂, t, s₁, s₂, h, f, π\_mod (64 repetitions), π\_fac, π\_df (128 repetitions) | ≈ 60 000 |

The figures are a guide. If SignMsg2 exceeds 2048 bytes, check the compact form and the field lengths first.

## Sources

- Adjedj, Blokh, Couteau, Galansky, Joux, Makriyannis. *Two-Round 2PC ECDSA at the Cost of 1 OLE* (version of
  6 March 2026), <https://eprint.iacr.org/2025/1950>.
- [crypto-bigint v0.7.0 release notes](https://github.com/RustCrypto/crypto-bigint/releases/tag/v0.7.0)
- [crypto-bigint documentation](https://docs.rs/crypto-bigint/)
- [crypto-primes documentation](https://docs.rs/crypto-primes/)
- [dashu-int documentation](https://docs.rs/dashu-int/)
