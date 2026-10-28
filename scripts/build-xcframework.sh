#!/usr/bin/env bash
# Builds TecdsaFFI.xcframework (device + simulator) and the Swift bindings.
# Output: target/xcframework/TecdsaFFI.xcframework and target/xcframework/swift/tecdsa_ffi.swift
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=target/xcframework
rm -rf "$OUT"; mkdir -p "$OUT/headers" "$OUT/swift"

for t in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build -p tecdsa-ffi --release --target "$t"
done

# Bindings are generated from the host library (metadata is embedded in it).
cargo build -p tecdsa-ffi --release --features bindgen
LIB=target/release/libtecdsa_ffi.dylib
[ -f "$LIB" ] || LIB=target/release/libtecdsa_ffi.so
cargo run -p tecdsa-ffi --release --features bindgen --bin uniffi-bindgen -- \
  generate --library "$LIB" --language swift --out-dir "$OUT/swift"

mv "$OUT/swift/tecdsa_ffiFFI.h" "$OUT/headers/"
mv "$OUT/swift/tecdsa_ffiFFI.modulemap" "$OUT/headers/module.modulemap"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libtecdsa_ffi.a -headers "$OUT/headers" \
  -library target/aarch64-apple-ios-sim/release/libtecdsa_ffi.a -headers "$OUT/headers" \
  -output "$OUT/TecdsaFFI.xcframework"

ls -lh target/aarch64-apple-ios/release/libtecdsa_ffi.a target/aarch64-apple-ios-sim/release/libtecdsa_ffi.a
echo "done: $OUT"
