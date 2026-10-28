#!/bin/sh
# Xcode pre-build step: builds libtecdsa_ffi.a (release, with the in-process benchmark server)
# for the SDK being built. Always release: debug numbers say nothing about the budgets.
set -eu

repo_root="$(cd "$SRCROOT/../.." && pwd)"
cargo_bin="${CARGO:-$(command -v cargo || true)}"
[ -n "$cargo_bin" ] || cargo_bin="$HOME/.cargo/bin/cargo"
[ -x "$cargo_bin" ] || { echo "cargo not found (set CARGO)" >&2; exit 1; }

case "$PLATFORM_NAME" in
  iphoneos) rust_target=aarch64-apple-ios ;;
  iphonesimulator) rust_target=aarch64-apple-ios-sim ;;
  *) echo "unsupported platform $PLATFORM_NAME" >&2; exit 1 ;;
esac

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
"$cargo_bin" build --manifest-path "$repo_root/Cargo.toml" -p tecdsa-ffi --lib --release \
  --features bench-server --target "$rust_target"
