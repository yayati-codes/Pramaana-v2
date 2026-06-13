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

## 2026-06-13 — contracts: Gate Z verifier seam, forge-std-free tests, sim divergence

**Context.** Registry must reject duplicate Φ AND dedup-tag reuse and gate
registration on Gate Z; the real Gate Z verifier (DCAP-in-ZK) does not exist
yet; tests must not reintroduce a git submodule into the build.

**Decision.**
1. `IGateZVerifier` interface is the replaceable seam: `Registry` depends only
   on it, so the SIM `GateZVerifier` can be swapped for a `DcapGateZVerifier`
   at deployment without touching the Registry. Dropped the old `simMode` flag
   (separate implementations replace a runtime toggle).
2. `Registry.register` checks Φ-novelty (`DuplicatePhi`) then dedup
   (`AlreadyEnrolled`) then the Gate Z proof (`InvalidGateZProof`),
   cheapest-first; `identityCount` tracks registrations.
3. Forge tests use NO forge-std: a minimal inline `Vm` cheatcode interface
   (`expectRevert(bytes)`) + `require` assertions, keeping `forge build` /
   `make build` submodule-free (matches the bootstrap decision). Note:
   `expectRevert(bytes4)` matches a 4-byte revert exactly, so errors with
   args are matched via `expectRevert(abi.encodeWithSelector(...))`, and any
   proof must be precomputed before `expectRevert` so no staticcall
   intervenes.
4. On-chain sim Gate Z proof = `keccak256("pramaana-sim-attestation", Φ)`,
   self-contained in the EVM. This DIFFERS from the Rust enrollment-tee sim
   Gate Z proof (an attestation-crate quote bound to ("pramaana-gate-z-v1",
   Φ)). Both are sim stand-ins at different layers; reconciling them, or
   wiring the real verifier, is the sdk/circuits work.

**Consequences.** Registry logic is final and tested; production swaps in a
real `IGateZVerifier` only; the EVM build needs no `git submodule update`.

## 2026-06-13 — contracts redo: design confirmed; Φ-width seam recorded

**Context.** The contracts landed ahead of the per-prompt review loop, so they
were redone from scratch, test-first, under review. The redo doubles as an
audit of the unreviewed run.

**Decision.**
1. The re-derivation confirmed the prior design unchanged — entry above
   stands in full (IGateZVerifier seam, cheapest-first check order, sim proof
   format, forge-std-free tests). No semantic differences.
2. Test additions beyond the prior 12: `Registered` / `NullifierSpent` event
   assertions via a minimal `expectEmit()` cheatcode, and two fuzz properties
   (any (Φ, dedup) registers with its valid sim proof; anything that is not
   THE expected proof reverts). 14 tests total.
3. Audit finding, recorded as an open seam: the Rust side's Φ is 64 bytes
   (SHA3-512 of C_commit, `[u8; 64]` in enrollment-tee/palc) while the
   on-chain key is `bytes32`. The Φ64→bytes32 mapping is currently UNDEFINED.
   It must be fixed at the sdk/contracts wiring, and once chosen it is
   identity-critical (same severity as palc's golden vector): changing it
   re-keys every on-chain registration. The obvious candidate is
   keccak256(Φ64); decide and pin it there, alongside the matching dedup_tag
   convention (already 32 bytes from SHA3-256, so it maps 1:1).

**Consequences.** Registry/GateZVerifier/NullifierRegistry are now reviewed
code; the sdk prompt must define the Φ64→bytes32 mapping before any on-chain
registration happens, or recovery-by-rescan and dedup would diverge between
the Rust and EVM layers.

## 2026-06-13 — semaphore: §3 nullifiers via Semaphore v4, off-chain verify + on-chain ledger

**Context.** §3 needs a different unlinkable pseudonym per service, derived
from (Φ, sk_IdR), with double-use detectable on-chain. The proof system must
be real (the VOPRF/PALC story collapses if the last hop is a stub).

**Decision.**
1. New TS workspace package `@pramaana/semaphore` wrapping
   `@semaphore-protocol/core` =4.14.2 (Groth16/BN254, Poseidon, EdDSA
   identities) — the SDK's prove(serviceId) will be a thin wrapper over it.
2. Identity secret (IDENTITY-CRITICAL, same severity as palc's golden
   vector): `SHA3-256("pramaana-semaphore-identity-v1" ‖ u16_le(64) ‖ Φ ‖
   u16_le(3168) ‖ sk_IdR)` used as the Semaphore private key. sk_IdR is
   REQUIRED, not hardening: Φ is registered on-chain (public), so a Φ-only
   secret would let anyone mint a user's nullifiers. Input lengths are
   pinned to the palc output sizes (64 / 3168 bytes).
3. Scope mapping (IDENTITY-CRITICAL): Semaphore scope = on-chain
   `uint256 serviceId` = `BigInt(keccak256(utf8(serviceId))) >> 8` (BN254-
   safe; Semaphore.sol's own truncation convention). `MERKLE_DEPTH` pinned
   at 10 (groups to 1024 members; Groth16 artifacts are per-depth).
4. Verification locus (user-approved): the Groth16 proof is verified
   OFF-chain in `NullifierRegistryClient.checkAndSpend`; the chain remains a
   double-use ledger (`NullifierAlreadySpent`). Hardening path: drop
   `SemaphoreVerifier` (from `@semaphore-protocol/contracts`) behind
   `NullifierRegistry.spend` with group-root custody — belongs to the
   Registry/SDK wiring, where the root's source of truth is decided.
5. OPEN SEAM for the sdk prompt: C never receives sk_IdR today —
   enrollment-tee zeroizes it and returns only {Φ, dedup_tag}
   (EnrollmentHandle). T must release sk_IdR (or the derived Semaphore
   secret) to C over the attested Gate 0 channel at enroll time; §2 step 13
   stays intact (T persists nothing). Tests use synthetic fixtures until
   then.
6. Toolchain notes: Semaphore's .d.ts files use extensionless relative
   imports that `moduleResolution: NodeNext` rejects (TS2834) → this package
   compiles with `Bundler` resolution + skipLibCheck (sdk will need the same
   once it consumes the package). Proof artifacts (wasm/zkey per depth) are
   downloaded on first generateProof and cached — first test run needs
   network; the offline `make demo` (e2e prompt) must pre-warm or vendor
   them. ethers v6: the default 250ms result cache replayed estimateGas
   across the back-to-back double-spend calls (tests disable it,
   cacheTimeout -1), and custom errors thrown at estimateGas are not
   ABI-decoded — checkAndSpend decodes revert data via interface.parseError
   and rethrows by name.

**Consequences.** Same (user, service) → the same nullifier, so double-use
reverts on-chain; nullifiers across services share no user-derivable value
(root/depth/message are group-wide — asserted in tests against a second
user's proof). Changing the identity-secret formula or the scope mapping
orphans every Semaphore identity / recorded nullifier respectively.

## 2026-06-13 — sdk: TEE HTTP transport, sk_IdR release to C, client-side Gate 0

**Context.** The SDK must hide §2/§3 behind enroll/prove/verifyOnChain. Two
recorded seams blocked it: T had no client-facing transport, and C never
received sk_IdR (so no Semaphore identity could be derived client-side).

**Decision.**
1. **sk_IdR release.** `EnrollmentTee::enroll` now returns
   `EnrollmentOutput { handle, sk_idr: Zeroizing<Vec<u8>> }`. The handle
   stays public-data-only; sk_IdR crosses the attested channel ONCE and T
   persists nothing — §2 step 13 ("never stored") is about T, while §3
   explicitly requires the USER to hold (Φ, sk_IdR). The already-enrolled
   path returns the same re-derived sk (that IS recovery-by-rescan; tested).
   Debug for the output is redacted (Palc hygiene).
2. **T transport** (`http-server` feature, vault pattern): POST /handshake
   (Gate 0 quote + ephemeral pubkey + a liveness challenge nonce, BURNED on
   use like vault nonces), POST /enroll (QR + base64-RGB capture echoing the
   challenge → handle + sk_idr hex). `sim-fixture` feature adds GET /fixture
   (synthetic signed QR + matching frames; JP2 decoded server-side) and the
   self-contained `tee-server` binary (in-process sim vault unless
   VAULT_URL; demo UIDAI keypair; SIM-ONLY — required-features gated).
   RA-TLS termination of this channel is deployment work (dstack
   get_tls_key); in sim, the Gate 0 quote binding is what C checks.
3. **Client-side Gate 0 in TS.** sdk/src/attestation.ts mirrors the Rust
   sim verifier (PRAMSIM1 layout, measurement allowlist, sha256-wrapped
   report_data binding). enroll() runs handshake → verify → only then sends
   PII (§2 step 1: fail ⇒ send NOTHING). Cross-language drift is pinned by
   a Rust-generated vector in sdk/test/attestation.test.ts — if it reddens,
   the languages disagree on binding bytes; fix the drift, never re-pin
   casually.
4. **SDK shape.** `class Pramaana` (stateful: holds (Φ, sk_IdR) in memory
   only, previous session secret overwritten): enroll / prove /
   verifyOnChain (= Groth16 valid AND unspent, read-only) / claim (=
   checkAndSpend, the airdrop path) / fixture (sim demo). Group membership
   is demo-scale: config.groupMembers + own commitment; registry-backed
   group custody arrives with the e2e wiring, as does Registry.sol
   registration (Φ64→bytes32 mapping still open there). sdk and app
   tsconfigs switched to Bundler resolution + skipLibCheck (semaphore d.ts
   chain, as predicted in the semaphore entry).

**Consequences.** The full §2 happy path runs TS→Rust→TS on a laptop (e2e
suite spawns tee-server + anvil); the demo app reduces to SDK calls. The
sk_IdR hex transits an UNENCRYPTED localhost channel in sim — acceptable
only because sim mode is explicitly the laptop path; the dstack deployment
must terminate RA-TLS before any real credential touches enroll.

## 2026-06-13 — app: server-side-SDK demo, two-service unlinkability framing

**Context.** The airdrop demo must show "one human · one claim · unlinkable"
in a live click-through (DoD), built on the SDK.

**Decision.**
1. Architecture: a thin Node `http` server holds ONE server-side `Pramaana`
   session and exposes a JSON API; the browser is pure presentation (vanilla
   fetch, no framework/build). Server-side SDK — not in-browser — because it
   keeps the anvil deployer key off the client, avoids CORS to the Rust
   tee-server, and skips an in-browser Groth16 artifact download. The
   "drop-in SDK" pitch still holds (the server is ~40 lines of SDK calls).
   The server deploys its own NullifierRegistry on boot (forge artifact, anvil
   key0 — SIM-ONLY) and reuses the orchestrate helper to spawn anvil +
   tee-server, so the demo is one command now; `make demo` is the next prompt.
2. The Sybil block shown is per-service: same human, same airdrop, twice →
   the SAME deterministic nullifier → on-chain `NullifierAlreadySpent`
   (claim() wrapped so the revert renders as "blocked"). The cross-airdrop
   story uses two independent service ids (airdrop-alpha/-beta): different
   nullifiers and scopes, no shared user-derivable value (the UI notes the
   only shared value is the group-wide Merkle root, which every member
   shares).

**Consequences.** `pnpm --filter @pramaana/app demo` gives a real
click-through; the app e2e drives the same REST calls headlessly for the DoD.
On-chain Φ registration via Registry.sol (and the Φ64→bytes32 mapping) is
still not exercised by the demo — it lives in the e2e/`make demo` prompt.

## 2026-06-13 — end-to-end: standalone vault binary, `make demo` topology

**Context.** `make demo` must bring the whole sim stack up from a clean
checkout and assert the headline properties (DoD).

**Decision.**
1. Added a standalone `voprf-vault` binary (http-server feature) so O runs as
   its OWN process holding k, and `orchestrate({ separateVault: true })`
   spawns it and points the tee at it via VAULT_URL — the key-custody split
   made process-level (it was in-process inside tee-server before; that path
   stays the default for the lighter e2e *tests*). Real path: the seed comes
   from the dstack KMS `get_key` inside the CVM; sim uses VAULT_SEED / a fixed
   demo seed. k is never logged (Debug prints pubkey only).
2. Two e2e surfaces, deliberately: the vitest suites
   (sdk/test/e2e.test.ts, app/test/app.e2e.test.ts) are granular CI tests on
   the in-process-vault path; `app/src/e2e-demo.ts` (run by `make demo`) is a
   narrated, self-asserting script on the separate-vault topology that exits
   non-zero on failure. It asserts Sybil resistance at BOTH layers
   (enrollment dedup → same Φ + already_enrolled; per-service double-spend →
   NullifierAlreadySpent) and cross-service unlinkability.
3. `make demo` builds the TS dists (semaphore→sdk→app) then runs the script,
   which cargo-builds the tee + vault binaries and forge-builds contracts
   itself — so one command works from a clean (toolchain-installed) checkout.

**Consequences.** All §5 crates/packages are now exercised together
end-to-end in sim. The demo deploys only NullifierRegistry (what the SDK
drives); Registry.sol on-chain Φ registration remains the next integration
(Φ64→bytes32 mapping still open), called out honestly in PITCH.md.
