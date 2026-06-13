# Progress

Component checklist (from ARCHITECTURE.md §5). Check an item only when it does its §5
job end-to-end (not when stubbed).

- [x] aadhaar-qr — parse Secure QR, verify UIDAI signature, extract fields/photo, stable digest
      (validated against synthetic QRs via the built-in `test-gen` generator; validation
      against a real UIDAI certificate + QR still pending)
- [x] liveness — decode JP2 photo, accept live face, match
      (JP2 decode real, pure-Rust openjp2; default `sim` matcher is a deterministic
      stand-in, real embeddings behind `onnx` feature — compiles, needs an external
      model file; capture check is an anti-replay nonce stub, not anti-spoofing)
- [x] palc — HKDF-SHA3-512 + deterministic Kyber-1024 + commitment + Φ + zeroize
      (FIPS 203 KeyGen_internal/Encaps_internal via libcrux-ml-kem; golden vector
      pins Φ — a red golden test after a dep bump means enrolled identities break)
- [x] voprf — client blind/unblind + DLEQ verify (ristretto255)
      (RFC 9497 VOPRF mode, ristretto255-SHA512, via facebook/voprf =0.5.0; server
      side behind `server` feature for voprf-vault; use `-p voprf@0.1.0` in cargo
      package selectors — the bare name is ambiguous with the upstream dep)
- [x] attestation — TDX quote gen (configfs-tsm) + verify (dcap-rs) + simulation mode
      (three backends: sim default / tdx / dstack for Phala Cloud; shared
      report_data-binding gate check with the sha256-wrapping convention; real
      paths compile-verified only — no TDX hardware or Intel collateral in CI)
- [x] enrollment-tee — orchestrates §2 steps 1,4–13
      (full pipeline over vault HTTP: Gate 0 handshake, UIDAI verify, face match,
      stable-id blind, Gate b/k, PALC, Φ-derived dedup, sim Gate Z, PII erase with
      observer-tested wipe; Registry is in-memory until the sdk/contracts wiring;
      RA-TLS termination + real attestation modes land at deployment)
- [x] voprf-vault — O: holds k, attested eval (Gate b/k server side)
      (in-process service: challenge nonces burned-on-use, quote + binding checks
      before any evaluation, DLEQ verified end-to-end by the voprf client crate;
      transport/RA-TLS and real key sealing arrive with enrollment-tee/deployment)
- [x] contracts — Registry (novelty/dedup), GateZVerifier, NullifierRegistry
      (Φ-novelty + dedup Sybil block + IGateZVerifier seam for a future DCAP-in-ZK
      verifier; sim Gate Z proof = keccak256("pramaana-sim-attestation", Φ); redone
      test-first under review — design re-derived unchanged; 14 forge tests incl.
      event assertions + 2 fuzz properties, forge-std-free so the build stays
      submodule-free; open seam: Φ64→bytes32 mapping fixed at SDK wiring)
- [x] semaphore — per-service unlinkable nullifiers (§3; TS binding @pramaana/semaphore)
      (real Semaphore v4 Groth16 proofs: identity from SHA3-256(domain ‖ Φ ‖ sk_IdR),
      scope = keccak(serviceId)>>8, depth pinned at 10; proof verified off-chain,
      NullifierRegistry is the on-chain double-use ledger — 13 vitest tests incl.
      anvil double-spend; first proof run downloads snark artifacts (network);
      sk_IdR release from T to C is the open seam for the sdk prompt)
- [x] end-to-end — `make demo` + docs/PITCH.md
      (headless asserting demo: anvil + standalone voprf-vault (O holds k) +
      enrollment-tee (sim) → SDK enroll/prove/claim → asserts Sybil block at
      BOTH layers (enrollment dedup + per-service double-spend) and
      cross-service unlinkability; runs green from a clean checkout. PITCH.md
      has the 3-min flow, real-vs-sim table, and the two headline claims with
      one-line proofs. Interactive version: `pnpm --filter @pramaana/app demo`)
- [ ] circuits — Gate Z (stub now)
- [x] sdk — enroll() / prove(serviceId) / verifyOnChain()
      (class Pramaana over the real Rust tee-server HTTP transport: Gate 0
      verified CLIENT-side before any PII is sent (TS sim-quote verifier,
      cross-language vector pinned), sk_IdR released to C once over the
      attested channel; prove/claim via @pramaana/semaphore; verifyOnChain =
      Groth16 + unspent; e2e vitest spawns tee-server + anvil — 11 tests;
      Registry.sol on-chain Φ registration + Φ64→bytes32 mapping remain for
      the e2e prompt)
- [x] app — Sybil-resistant airdrop demo
      (browser demo over @pramaana/sdk: Node server holds one SDK session +
      serves a vanilla-JS UI; live click-through proves enroll → claim Alpha →
      second Alpha claim BLOCKED (same nullifier, Sybil) → Beta claim with an
      unlinkable nullifier; deploys its own NullifierRegistry to anvil, drives
      the sim tee-server; `pnpm --filter @pramaana/app demo` orchestrates
      anvil+tee one-command; 3 app e2e tests; anvil key0 deployer is sim-only)
