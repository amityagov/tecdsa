# Security policy

`tecdsa-1ole` has **not been audited**. Do not protect real funds with it before an independent audit;
[`docs/AUDIT.md`](docs/AUDIT.md) lists what was checked and what was not.

## Reporting a vulnerability

Please do not open a public issue or pull request for a security problem.

Report it privately through GitHub: **Security → Report a vulnerability** on
<https://github.com/amityagov/tecdsa/security/advisories/new>. Include the affected version or commit, what an
attacker can do, and a reproduction if you have one.

You can expect an acknowledgement within a week. The fix is prepared privately and published together with an
advisory; reporters are credited unless they prefer otherwise.

## Scope

In scope: the protocols and math in `tecdsa-core` (key generation, signing, the zero-knowledge proofs, setup
verification, message parsing, secret handling) and the `tecdsa-ffi` bindings.

Out of scope: the example app in `examples/ios`, the `bench-server` feature (it runs the server inside the
client and must never be enabled in a product), and issues that need the application to misuse the API, such
as not pinning the hash of `SetupData`.

## Supported versions

Only the latest release and `main` receive fixes.
