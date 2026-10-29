# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/); while the version is `0.x`, minor releases may
break the API and the wire format.

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
