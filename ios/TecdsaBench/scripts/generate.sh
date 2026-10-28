#!/bin/sh
# Generates the Swift bindings (Generated/) and the Xcode project.
# Usage: DEVELOPMENT_TEAM=XXXXXXXXXX ios/TecdsaBench/scripts/generate.sh
set -eu
cd "$(dirname "$0")/.."
root="$(cd ../.. && pwd)"
rm -rf Generated; mkdir -p Generated

cargo build --manifest-path "$root/Cargo.toml" -p tecdsa-ffi --release --features "bindgen bench-server"
lib="$root/target/release/libtecdsa_ffi.dylib"
cargo run -q --manifest-path "$root/Cargo.toml" -p tecdsa-ffi --release --features "bindgen bench-server" \
  --bin uniffi-bindgen -- generate --library "$lib" --language swift --out-dir Generated
mv Generated/tecdsa_ffiFFI.modulemap Generated/module.modulemap

DEVELOPMENT_TEAM="${DEVELOPMENT_TEAM:-}" xcodegen generate
echo "open TecdsaBench.xcodeproj"
