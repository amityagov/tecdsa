# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/); while the version is `0.x`, minor releases may
break the API and the wire format.

## [0.2.0]

**Wire format of key generation changes** (`KgMsg2`); signing and stored data are unchanged.

- `ℓ0` of Π_df* is 32, the value the paper's parameter table assumes (it was 8). A cheating client could
  pass a small-subgroup check with probability up to `2^-112` before; now `2^-128`. The proof mask is
  `±2^{2ℓ+2ℓ0+ν}` (the paper's `ν_df* = ℓ0 + 64`), which also gives the full 64 bits of hiding.
  Π_df* grows from 720 to 928 B and `KgMsg2` from 1842 to 2050 B; prove and verify stay in the same few
  milliseconds.
- Existing setups and shares keep working: `ℓ0` only shapes the key-generation proof, and the setup
  encoding, the setup hash, the shares and signing do not depend on it (test
  `setup_and_shares_do_not_depend_on_l0`). A new key generation needs the client and the server on 0.2.0.
- `vectors/reduced.json` regenerated.

## [0.1.3]

Hardening after an independent review. No change to the wire format or the parameters.

- The client refuses degenerate server setup values (`ρ = 1`, `t`, `s₁`, `s₂` equal to ±1, equal DF values,
  `N̂ = N`).
- `ClientKeyShare::save` and `ServerKeyShare::save` no longer overwrite an existing share and fail with
  `Error::AlreadyExists`; `replace` overwrites on purpose. The FFI maps it to `TecdsaError.AlreadyExists`, so a
  malicious server cannot destroy a stored share by restarting key generation under a known wallet id.
- FFI: `ClientSetup.verifyPinned` checks the pinned setup hash first; `benchServerEnabled()` lets a product
  assert that the benchmark server is not built in.
- Regression test for the DF part of Π_sig (`z1` shifted by `N·q`); `docs/AUDIT.md` records why that part is
  required, the real soundness numbers for `ℓ0 = 8` and the known limitations (zeroization, public chain code).

## [0.1.2]

- Fixed the 112-bit profile (`PARAMS_112`, benchmark only): its tough-prime shape did not fit into the
  1024-bit primes, so setup and client key generation failed (`InvalidInput` through the FFI). The
  factors of `(p-1)/2` are now 5 × 205 bits for the server and are sized to fill the prime for the client.
  The 128-bit profile and the wire format are unchanged. Added `tecdsa-ffi/tests/e2e_112.rs`.

## [0.1.1]

No change to the protocols or the wire format.

- Dev-dependencies: `dashu-int` and `dashu-base` 0.6 (test oracle and the optional `vartime-dashu` backend),
  `criterion` 0.7.
- `cargo-deny` runs with `--all-features`; the bindings generator's MPL-2.0 crates are allowed and the
  unmaintained `basic-toml` (build-time only, through `uniffi_bindgen`) is ignored.
- Added `SECURITY.md`, this changelog, README badges and CI on GitHub.

## [0.1.0]

First release. Implements *Two-Round 2PC ECDSA at the Cost of 1 OLE* (ePrint 2025/1950) on secp256k1.

- Server setup with Π_mod, Π_fac and Π_df proofs; client verification of the setup.
- Key generation (three messages) and signing (two rounds plus an optional third message).
- BIP32 non-hardened derivation: signatures under `X + δ·G`.
- Pure Rust, `no_std` + `alloc` core, no native dependencies; secrets are `ZeroizeOnDrop`.
- `tecdsa-ffi`: UniFFI bindings for the client side (Swift), a `SecretStore` trait, an XCFramework build script.
- Test vectors that pin the wire format, fuzz targets for the message and proof parsers.
- Not audited; see `docs/AUDIT.md`.

[0.1.1]: https://github.com/amityagov/tecdsa/releases/tag/v0.1.1
[0.1.0]: https://github.com/amityagov/tecdsa/releases/tag/v0.1.0
