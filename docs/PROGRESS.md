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
- [ ] palc — HKDF-SHA3-512 + deterministic Kyber-1024 + commitment + Φ + zeroize
- [ ] voprf — client blind/unblind + DLEQ verify (ristretto255)
- [ ] attestation — TDX quote gen (configfs-tsm) + verify (dcap-rs) + simulation mode
- [ ] enrollment-tee — orchestrates §2 steps 1,4–13
- [ ] voprf-vault — O: holds k, attested eval (Gate b/k server side)
- [ ] contracts — Registry (novelty/dedup), GateZVerifier, NullifierRegistry
- [ ] circuits — Gate Z (stub now)
- [ ] sdk — enroll() / prove(serviceId) / verifyOnChain()
- [ ] app — Sybil-resistant airdrop demo
