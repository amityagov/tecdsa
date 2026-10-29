# Comparison with the `mpc-lib` reference (Fireblocks, MPC-BAM)

This is a reading-based comparison with the public `mpc-lib` implementation of the same protocol
family (MPC-BAM). It compared the BAM signature (`bam_ecdsa_cosigner*.cpp`), `bam_well_formed_proof.cpp`,
the `ZKPOK_OPTIM_*` constants and the server-side setup generation. **Not read:** the whole of client and
server keygen, add-user/redistribute, the persistence layers, the reference's tests. The reference was
neither built nor run; the conclusions come from reading the code. The reference cites the version of the
paper from 2025-06-01, this code cites the version of 6 March 2026.

## What matches

- Signature structure: the server sends `R₂ = g^{k₂}` and `Y = X₁^{k₂}`; the client checks `R₂^{x₁} = Y`,
  sends `R₁`, `R = R₂^{k₁}`, the ciphertext and the proof; `r = x(R + R₁^{e})` with the shift
  `e = H(X, R₁, R, m, …)`; `s = dec(S)·(k₂+e)⁻¹`.
- The server checks `R = R₁^{k₂}`, re-centers `dec(S)` around `N/2` before reducing mod q, normalizes
  low-s with the recovery-id correction and verifies the final ECDSA signature.
- Setup: the same proofs (Π_mod, Π_fac, Π_df), the same Π_fac group `d = 2^3459 + 1169115`; `h, f` are derived
  from the setup identifier (the same resolution of the circular dependency as here).
- Sizes: `n_a` = 1024 bits (128 B), `n_b` = 448 bits (56 B), ε = 192 bits (24 B), `z₁` 152 B, `z₂` 80 B
  (here +1 sign byte).

## Differences that matter for security

1. **Zero digest.** The reference rejects `m ≡ 0 (mod q)` (Claim 7.15 of the paper) on both sides. This code
   lacked the check. **Fixed:** `sign::check_digest` in `ServerSign0::start` and `ClientSign::respond`, test
   `zero_digest_is_rejected_by_both_sides`.
2. **Π_sig without the DF part in the reference.** The reference proof contains only `D, U, V, z₁, z₂, w₀, w₂`;
   there is no `P̃, B̃, w₁`. This version (following the 2026 paper) adds the DF commitment
   `P̃ = s₁^a s₂^b t^µ` and the related equation. It is not established whether that part is needed for
   soundness or only tightens the proof relative to the 2025 version; this is a **question for the authors**.
3. **Range of λ₀.** Reference: `n_λ0 = max(n_a + 2ℓ + ν, n_b + n_λ + ε) + ν` = 1408 bits (176 B), response
   `w₂` 200 B. Here: `n_λ + ε + n_b + ν` = 1024 bits, `w₂` 153 B. These come from different versions of the
   paper; to be checked against the paper and with the authors.

## Scope

Only BAM is needed: 2-of-2 ECDSA (client + server) on secp256k1, plus HD derivation. CMP, EdDSA, FROST,
other curves, add-user and redistribute are not implemented.

## HD derivation: implemented

BAM supports it, and it is implemented in the same way as the reference (`tecdsa-core/src/hd.rs`): BIP32,
**non-hardened** indices only (hardened ones need the private key and are rejected), a chain of 1–16 levels
(BIP44 is 5). `δ` is the sum of the BIP32 tweaks along the path, computed from the public key `X` and the
chain code, so both sides get the same value. The client adds `δ` to its share and the server leaves its own
unchanged; the signature is made under `X + δ·G`, and that key enters `Y`, `e` and the `ssid`. A path
mismatch between the parties is caught by the client's check `Y = R₂^{x₁+δ}`. Tests: the first level of
BIP32 test vector 2 matches; end-to-end signatures over several paths verify under the derived key and
fail under the master key; the recovery id recovers the derived key. Difference from the reference: it
accepts hardened indices and silently hashes a zero "private key" (because of the call with `privkey = 0`);
this code rejects them explicitly.

## What is still missing

- Batch signing of several blocks per call and the `POSITIVE_R` mode (needed for Stark, not for secp256k1).
- **Server state between rounds.** The reference keeps `k₂` through a persistence interface with
  `load_signature_data_and_delete` (single use). Here the `ServerSign1` state lives in memory and is not
  serializable, so a server without session affinity (several processes behind a load balancer) cannot be
  built yet. This has to be solved before integration.

## Implementation differences

- Nonce: the reference takes a random `k` from a generator, this code uses a hedged one (a hash of fresh
  randomness, the secret and the context).
- The reference verifies Π_sig **with the Paillier private key** (`commit_with_private`, computing mod p² and
  mod q²); here verification uses the public key. This is a possible speed gain on step S3 (currently 38 ms
  against a 40 ms budget). It applies only because the verifier owns the key.
- Session binding: the reference uses AAD made of `key_id`, `server_id`, `client_id`, `tx_id`; here the
  `ssid` (hash of the setup, party ids, `key_id`, digest, `R₂`).
- The reference checks `gcd(S, N) = 1`; here `check_ciphertext` checks `S ∈ Z*_{N²}`.

## Open items

1. Ask the authors about points 2 and 3 (the DF part of Π_sig, the range of λ₀) together with ℓ0.
2. Decide whether batches are needed and how to store the server state between rounds (depends on the
   integration).
3. Optional: verify Π_sig through CRT with the private key on the server.
4. A cross-compatibility test is not possible while the protocols differ in format and paper version.
