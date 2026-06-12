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
