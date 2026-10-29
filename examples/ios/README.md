# iOS example sources

Swift sources only, no Xcode project, so they can be read here and dropped into your own app.

| File | What it shows |
| --- | --- |
| `KeychainStore.swift` | A `SecretStore` backed by the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`): the client's key share never leaves the device and needs an unlocked phone. This is the file to copy. |
| `Bench.swift` | Runs setup verification, key generation and signing against the in-process server and reports timings. |
| `TecdsaBenchApp.swift` | A small SwiftUI screen that runs the benchmark and shows or shares the report. |

They are written against the Swift bindings of `tecdsa-ffi`. To use them:

1. Build the library and the bindings with `scripts/build-xcframework.sh` (see the root README).
2. Add `TecdsaFFI.xcframework` and the generated `tecdsa_ffi.swift` to your app target.
3. Add the Swift files you need. `Bench.swift` and `TecdsaBenchApp.swift` also need the in-process server,
   so build `tecdsa-ffi` with the `bench-server` feature. That feature is for benchmarking only and must
   not be enabled in a product build.
