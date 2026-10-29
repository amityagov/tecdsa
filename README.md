# tecdsa-1ole

[![crates.io](https://img.shields.io/crates/v/tecdsa-core.svg)](https://crates.io/crates/tecdsa-core)
[![docs.rs](https://img.shields.io/docsrs/tecdsa-core)](https://docs.rs/tecdsa-core)
[![CI](https://github.com/amityagov/tecdsa/actions/workflows/ci.yml/badge.svg)](https://github.com/amityagov/tecdsa/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/tecdsa-core.svg)](#license)

**Two-party ECDSA on secp256k1 in pure Rust.** A mobile client and a server hold one key in two shares
and sign together, in **two rounds** and about **2 KB** of traffic. The private key never exists in one
place. The signature is an ordinary ECDSA signature that any Bitcoin or Ethereum verifier accepts.

It implements [*Two-Round 2PC ECDSA at the Cost of 1 OLE*](https://eprint.iacr.org/2025/1950)
(Adjedj, Blokh, Couteau, Galansky, Joux, Makriyannis; ePrint 2025/1950).

> **Status: not audited.** This is a research-grade implementation of a recent protocol. It has not
> been reviewed by an external party. Do not protect real funds with it before an independent audit.
> [`docs/AUDIT.md`](docs/AUDIT.md) lists what was checked and what was not.

## Why this crate

- **Fast on a phone.** On an iPhone 16 Pro the client step of a signature takes about **36 ms**, and
  client key generation about **124 ms** (median). See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).
- **Pure Rust, no native code.** No GMP, OpenSSL or `-sys` crates, so `cargo build --target aarch64-apple-ios`
  needs no C toolchain. Licenses are MIT, Apache-2.0 or BSD; `cargo deny` enforces it.
- **Small messages.** A signature is `SignMsg1` (70 B), `SignMsg2` (about 1.9 KB), and an optional
  `SignMsg3` (70 B).
- **Built for hostile input.** `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic` in the core;
  secrets are `ZeroizeOnDrop`; every proof has negative tests for each field; parsers are fuzzed.
- **Transport and storage are yours.** The crate takes and returns bytes, and stores shares through a
  `SecretStore` trait that you implement (Keychain on iOS, for example).
- **HD wallets.** BIP32 non-hardened derivation is supported: sign under `X + δ·G` for any path.

## How it works

```
 Server (S)                                        Client (C, phone)

 setup, once ─────────── SetupData (≈60 KB) ────────►  verify and pin its hash

 keygen, once per wallet
 KgMsg1  ─────────────────────────────────────────►
         ◄──────────────────────────────────────── KgMsg2
 KgMsg3  ─────────────────────────────────────────►  both sides hold a share of X

 sign, per transaction
 SignMsg1 ────────────────────────────────────────►
          ◄─────────────────────────────────────── SignMsg2   (with a zero-knowledge proof)
 (r, s, recovery id)                                 optional SignMsg3 back to the client
```

The server owns a Paillier key and proves, once, that its parameters are well formed. The client
encrypts its half of the signature computation under that key and proves in zero knowledge that it did
so correctly; the server decrypts, finishes the signature and verifies it before returning it. Seven
zero-knowledge proofs (Π_mod, Π_fac, Π_df, Π_df*, Π_dlog, Π_dlenc, Π_sig) back the protocol.

The full design, parameters and wire format are in [`docs/SPEC.md`](docs/SPEC.md).

## Repository layout

| Path | What it is |
| --- | --- |
| `tecdsa-core/` | The protocols and math. `no_std` + `alloc`, no I/O. |
| `tecdsa-ffi/` | [UniFFI](https://mozilla.github.io/uniffi-rs/) bindings for the client side, for Swift. |
| `fuzz/` | libFuzzer targets for the message and proof parsers. |
| `vectors/` | Deterministic test vectors that pin the wire format. |
| `examples/ios/` | Swift sources: a Keychain `SecretStore` and an on-device benchmark. |
| `scripts/` | `build-xcframework.sh`: builds `TecdsaFFI.xcframework` for device and simulator. |
| `docs/` | Specification, benchmarks, audit notes. |

## Building and testing

You need Rust 1.85 or newer (edition 2024). Linux and macOS are supported.

```sh
cargo build --release
cargo test --workspace --release        # release: the proofs use full-size 3072-bit numbers
cargo clippy --workspace --all-targets -- -D warnings
```

Slow full-size proof tests and the constant-time check are marked `#[ignore]`:

```sh
cargo test -p tecdsa-core --release --lib zk -- --ignored
cargo test -p tecdsa-core --release --test ct -- --ignored     # run on a quiet machine
cargo bench -p tecdsa-core --bench arith
```

`tecdsa-core` also builds without default features (`no_std` + `alloc`):

```sh
cargo build -p tecdsa-core --no-default-features
```

### Cargo features of `tecdsa-core`

| Feature | Enables |
| --- | --- |
| `std` | `std` support in the error, serde and postcard dependencies |
| `getrandom` | OS randomness (`OsRng`) |
| `vartime-dashu` | Variable-time `dashu-int` backend for public-data operations on the server |

### Where to look for usage

The end-to-end tests are the best examples: `tecdsa-ffi/tests/e2e.rs` drives key generation and signing
through the same API Swift sees, and the tests in `tecdsa-core/src/sign/` and `tecdsa-core/src/keygen/`
run both parties in one process.

## iOS

`tecdsa-ffi` exposes the client side to Swift through UniFFI: verifying the server setup, key
generation, signing (with optional HD path), and a `SecretStore` protocol for you to back with the
Keychain.

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
scripts/build-xcframework.sh     # target/xcframework/TecdsaFFI.xcframework + Swift bindings
```

[`examples/ios/`](examples/ios) holds Swift sources only (no Xcode project, so the repository builds on
Linux and carries no signing identifiers): a Keychain-backed `SecretStore` and a SwiftUI benchmark that
runs the whole protocol on a device. The benchmark needs the `bench-server` feature of `tecdsa-ffi`,
which runs the server inside the process. **Never enable it in a product build.**

## Security

- The code has not been audited. Read [`docs/AUDIT.md`](docs/AUDIT.md) for the review map, the list of
  deviations from the paper and the open questions.
- Authenticating the server setup is the application's job. The crate returns a hash of `SetupData`;
  pin it in your app or have it signed by a long-term server key.
- Keeping the server's state between the two signing rounds is not implemented yet: `ServerSign1` lives in
  memory, so one signing session must stay on one process.
- Fuzzing so far was short (40 s per target). A 24-hour run per target is still to do.

To report a vulnerability, please do not open a public issue; follow [`SECURITY.md`](SECURITY.md).

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/SPEC.md`](docs/SPEC.md) | Design specification: parameters, protocols, proofs, encodings |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Measured performance on desktop and iPhone |
| [`docs/AUDIT.md`](docs/AUDIT.md) | Map for reviewers, ZK checklist, deviations, fuzzing |
| [`CHANGELOG.md`](CHANGELOG.md) | Release notes |
| [`docs/COMPARISON-mpc-lib.md`](docs/COMPARISON-mpc-lib.md) | Comparison with the `mpc-lib` implementation of the same protocol family |

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your
option. `tecdsa-ffi` links [UniFFI](https://github.com/mozilla/uniffi-rs), which is MPL-2.0.
