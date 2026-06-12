# Decisions

Architecture/implementation decision log. One entry per decision:
`## YYYY-MM-DD — Title`, then Context / Decision / Consequences.

## 2026-06-12 — aadhaar-qr: stable digest scope, decompression, field layout

**Context.** The Secure QR's trailing 256-byte RSA signature covers the issuance
timestamp, and UIDAI re-issues QRs with fresh timestamps for the same person.

**Decision.**
1. `stable_digest` = SHA-256 over the *signed message* (decompressed payload
   MINUS the trailing 256 signature bytes) with the 17 timestamp bytes of the
   referenceId zeroed. Including the signature would make digests differ across
   re-issues, since the signature covers the timestamp.
2. Decompression is tolerant: zlib → gzip → raw DEFLATE. Real UIDAI QRs are
   gzip-wrapped; the spec is commonly described as zlib; the test generator
   emits zlib.
3. Field layout constant: 16 text fields each terminated by 0xFF (version,
   referenceId = last-4 + 17-digit timestamp, name, DOB, gender, 11 address
   fields), then the JPEG2000 photo, then the signature. 0xFF cannot occur in
   UTF-8 text, so only the photo region may contain it; splitting stops after
   the 16th delimiter.

**Consequences.** Re-scan and re-issue determinism holds (§4); signature
verification runs before any field is interpreted; a real-QR fixture should be
added later to pin the layout against UIDAI ground truth.

## 2026-06-12 — liveness: JP2 backend, fixture, matcher design

**Context.** §2 step 5 needs JP2 decode + face match in-enclave; tests must
run without ML models or a real Aadhaar. No cmake on dev machines.

**Decision.**
1. JP2 decoding via `jpeg2k` with the pure-Rust `openjp2` backend
   (`openjpeg-sys` needs cmake). openjp2 is a c2rust translation that keeps
   C's free(NULL) idiom, which Rust debug UB-checks abort on during codec
   teardown — `[profile.dev.package.openjp2] debug-assertions = false` runs it
   exactly as it ships in release builds. Revisit if openjp2 > 0.6.1 fixes it;
   a TEE production build should use the C openjpeg via `openjpeg-sys`.
2. aadhaar-qr's testgen photo is now a REAL 64x64 JP2 (box format, like
   genuine Aadhaar photos): `crates/aadhaar-qr/testdata/synthetic_face.jp2`,
   generated once with PIL (command in the commit message).
3. Default `sim` matcher: 8x8 block-luma fingerprint, mean-centered,
   L2-normalized, cosine → [0,1]. Deterministic stand-in, NOT face
   recognition; real path is `onnx` (ort `=2.0.0-rc.12`, exact pin because
   pre-release rc bumps break API).

**Consequences.** Demo and CI run with zero ML deps; `--features onnx` is
compile-gated only until a model file is provisioned; threshold semantics are
uniform (mapped cosine in [0,1]) across both matchers.

## 2026-06-12 — palc: exact KeyGen-from-seed construction

**Context.** §2 step 10 needs deterministic ML-KEM-1024 keys from the HKDF
seed; Φ and sk_IdR must be exactly recomputable forever (recovery-by-rescan).

**Decision.** No DRBG shim: libcrux-ml-kem's explicit-randomness API IS the
FIPS 203 derandomized form. The exact construction:

```
h_stable = SHA3-512(stable_id)
seed     = HKDF-SHA3-512(salt = 64 zero bytes, IKM = oprf_output ‖ h_stable,
                         info = "pramaana-v1", L = 64)
(ek, dk) = ML-KEM-1024.KeyGen_internal(d = seed[0..32], z = seed[32..64])
m        = SHA3-512(seed)[0..32]
(ct, K)  = ML-KEM-1024.Encaps_internal(ek, m)        (K discarded + wiped)
C_commit = ek ‖ ct          (1568 + 1568 = 3136 bytes)
Φ        = SHA3-512(C_commit);  sk_IdR = dk (3168 bytes)
```

Deviation from the spec sketch: "Enc(pk, sha3_512(seed))" cannot take a
64-byte plaintext — ML-KEM's message space is exactly 32 bytes — so m is
SHA3-512(seed) truncated to 32 bytes.

**Consequences.** Both `*_internal` functions are fully specified by FIPS 203,
so any compliant implementation reproduces identical (ek, dk, ct): Φ survives
KEM-crate swaps. A golden test pins Φ for fixed inputs; if it reddens after a
dependency bump, the derivation moved and enrolled identities would break —
investigate, never just re-pin. Zeroization scope: every buffer palc
allocates is wiped before `derive` returns (verified by a post-wipe observer
test); sha3/hkdf internal states and libcrux's by-value seed copy are not
reachable through their APIs — the enclave boundary is the backstop there.

## 2026-06-12 — voprf: wrap facebook/voprf 0.5.0 rather than hand-roll

**Context.** §2 steps 6–9 need client blind/unblind + DLEQ verification; the
VOPRF is the load-bearing privacy mechanism (THREAT_MODEL b), so a maintained,
widely-used RFC 9497 implementation beats a bespoke Chaum-Pedersen.

**Decision.** Wrap `voprf =0.5.0` (facebook/voprf; exact pin — 0.6 is a
pre-release), VOPRF mode, ciphersuite ristretto255-SHA512, curve25519-dalek 4
underneath. Our package is also named `voprf`, so the dependency is renamed
`voprf_rfc9497 = { package = "voprf", ... }`; cargo resolves both, but bare
`-p voprf` selectors are ambiguous — use `-p voprf@0.1.0`. Server-side
evaluation (`Vault`, including RFC 9497 DeriveKeyPair via `from_seed`) ships
behind the `server` feature for voprf-vault and tests. Finalize output is 64
bytes (SHA-512), satisfying palc's MIN_OPRF_OUTPUT_LEN = 32.

**Consequences.** Blindness is information-theoretic (uniform r makes
r·H(x) uniform regardless of x) — the statistical test is wiring smoke-test
only. DLEQ verification is what pins evaluations to the committed vault key;
the test suite covers the per-user-key attack (honest proof from a rogue key
verified against the committed pk must fail). Ristretto encoding structure:
bit 0 (parity; "non-negative" = even) and bit 255 are always zero — the
blindness test asserts this structure explicitly and bounds bits 1..=254.

## 2026-06-13 — attestation: three backends + the sha256(report_data) convention

**Context.** §2 gates 0/b/k/Z need quotes on a laptop (sim), a bare TDX host,
and Phala Cloud (dstack), with one shared binding check.

**Decision.**
1. Backends: `sim` (default; 120-byte mock quote `PRAMSIM1 ‖ measurement ‖
   stored_report_data`), `tdx` (configfs-tsm 0.0.2 gen; tdx-quote 0.0.5
   parse + QE signature; dcap-rs 0.1.0 full DCAP v4 verification when Intel
   collateral is supplied), `dstack` (dstack-sdk 0.1.3 over
   /var/run/dstack.sock; also serves RA-TLS certs via get_tls_key; quotes are
   plain TDX quotes — verify them with the tdx verifier).
2. report_data convention: `bind_report_data(nonce, value)` =
   SHA-512("pramaana-report-data-v1" ‖ u64_le(len(nonce)) ‖ nonce ‖ value)
   (domain-separated §4, length-framed). The quote FIELD stores
   `sha256(report_data) ‖ 0^32`. Verified from dstack-sdk 0.1.3 source: its
   `get_quote` passes raw bytes (≤ 64, README says hash longer inputs
   yourself), and configfs-tsm likewise — so every Attester SUBMITS the
   sha256-wrapped form, making the convention hold by construction on all
   three backends and letting one `verify_report_data_binding` serve every
   gate.
3. dcap-rs 0.1.0 sharp edge: its parsers panic on malformed input —
   pre-validate with tdx-quote parsing before the collateral path.
   dstack-sdk pulls `alloy` (heavy) — acceptable because feature-gated.

**Consequences.** Gate logic is backend-independent; CI exercises sim fully
while tdx/dstack stay compile-verified (no hardware/collateral in CI);
replay of an old quote under a fresh nonce fails the binding check by
construction.

## 2026-06-13 — enrollment-tee: stable_id encoding, Φ-derived dedup tag, vault HTTP

**Context.** T orchestrates §2 steps 1, 4–13; the dedup tag goes on-chain;
recovery-by-rescan requires the stable-id bytes to be reproducible forever.

**Decision.**
1. stable_id (§2 step 6) = `"pramaana-stable-id-v1" ‖ (u16_le(len) ‖ field)`
   for last-4, name, DOB, gender, pincode — length-framed so field
   boundaries cannot collide. These bytes are identity-critical: changing
   them re-keys every enrollment (same severity as palc's golden vector).
2. dedup_tag (§2 step 11) = SHA3-256("pramaana-dedup-v1" ‖ Φ). Derived
   THROUGH Φ — and therefore through the issuer-unknown k — never from QR
   fields: an on-chain tag computable from QR data would let UIDAI enumerate
   its database and de-anonymize (CLAUDE.md non-negotiable).
3. Gate Z (sim) proof = attestation quote with report_data bound to
   ("pramaana-gate-z-v1", Φ); the registry verifies quote + binding before
   recording. Registry is a trait; InMemoryRegistry mirrors Registry.sol
   until the sdk/contracts wiring; the real ZK circuit is the circuits task.
4. Vault transport: JSON-over-HTTP (tiny_http server feature in voprf-vault,
   ureq client in T). The client PINS the vault pubkey at construction —
   Gate k DLEQ verification always runs against the committed key. RA-TLS
   termination is deployment work (dstack get_tls_key).
5. SIMULATION env semantics: unset/"1"/"true" ⇒ sim; any other value ⇒
   UnsupportedMode until tdx/dstack are wired into T at deployment.

**Consequences.** The full §2 sequence runs end-to-end on a laptop; re-scan
and re-issue reproduce the same Φ and dedup blocks a second mint; sk_IdR
exists only inside enroll() and is zeroized on drop, never persisted.
