# tecdsa-1ole

Pure-Rust 2PC ECDSA (secp256k1) after "Two-Round 2PC ECDSA at the Cost of 1 OLE" (ePrint 2025/1950).
See `PLAN.md` for the staged plan and the spec (`ТЗ 2PC ECDSA (1 OLE) на чистом Rust.md`).

## iOS example

The iPhone benchmark app (SwiftUI, Keychain-backed share, in-process server through the
`bench-server` feature of `tecdsa-ffi`) lives in a separate repository, `tecdsa-ios-example`, so
this repository stays buildable on Linux and free of signing identifiers. Clone it next to this
one and run its `scripts/generate.sh`.
