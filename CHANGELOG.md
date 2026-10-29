# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/); while the version is `0.x`, minor releases may
break the API and the wire format.

## [0.1.0]

First release. Implements *Two-Round 2PC ECDSA at the Cost of 1 OLE* (ePrint 2025/1950) on secp256k1.

- Server setup with Π_mod, Π_fac and Π_df proofs; client verification of the setup.
- Key generation (three messages) and signing (two rounds plus an optional third message).
- BIP32 non-hardened derivation: signatures under `X + δ·G`.
- Pure Rust, `no_std` + `alloc` core, no native dependencies; secrets are `ZeroizeOnDrop`.
- `tecdsa-ffi`: UniFFI bindings for the client side (Swift), a `SecretStore` trait, an XCFramework build script.
- Test vectors that pin the wire format, fuzz targets for the message and proof parsers.
- Not audited; see `docs/AUDIT.md`.

[0.1.0]: https://github.com/amityagov/tecdsa/releases/tag/v0.1.0
