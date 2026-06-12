# Pramaana v2 Architecture — Aadhaar Variant

## §1 Participants
- C  = Client (phone/browser)
- T  = Enrollment TEE (attested confidential VM, Intel TDX)
- O  = VOPRF Vault holding key k, in its own TDX CVM
- R  = Registry (on-chain, EVM)

## §2 Enrollment sequence (full v2; only steps 2 & 5 differ from ePassport)
1. Gate 0 — C asks T to start. T returns an RA-TLS quote proving genuine enclave +
   reviewed code, with report_data = H(nonce ‖ ephemeral_TLS_pubkey). C verifies the
   appraisal policy; if it fails, C stops and sends NOTHING.
2. [CHANGED] C scans the Aadhaar Secure QR and extracts (signed_data, UIDAI_signature).
   (This replaces "read passport NFC chip".)
3. C records a live face capture + device check (liveness). [UNCHANGED]
4. C sends QR signed_data + signature + liveness artifacts to T over the RA-TLS channel.
5. [CHANGED] T verifies the UIDAI RSA-2048/SHA-256 signature over signed_data against the
   UIDAI public certificate; extracts demographic fields + the JPEG2000 photo; and matches
   the live face to the QR photo INSIDE the enclave. (This replaces NFC passive/active auth;
   liveness is preserved.)
6. T computes a STABLE identifier from timestamp-stripped reference fields
   (last-4 ‖ name ‖ DOB ‖ gender ‖ pincode), then BLINDS it so the vault can't read it.
7. Gate b — T presents a quote to O with report_data bound to the blinded input
   (prevents replay-based grinding). O verifies T's quote.
8. O evaluates the VOPRF with sealed key k and returns the evaluation + a DLEQ proof.
9. Gate k — T verifies O's proof that k lives in a genuine sealed TDX CVM, then unblinds.
10. PALC — T derives:
      seed = HKDF-SHA3-512(salt=0^512, IKM = oprf_output ‖ H(stable_id), info="pramaana-v1", L=64)
      (pk_IdR, sk_IdR) = Kyber1024.KeyGen(seed)
      C_commit = pk_IdR ‖ Kyber1024.Enc(pk_IdR, H(seed))
      Φ = H(C_commit)              // master identity
11. Dedup — T computes a per-person dedup tag and queries R.
      seen  → return existing identity (Sybil block; do NOT mint a second).
      new   → continue.
12. Gate Z — T produces a ZK proof that C_commit came from reviewed code on approved
    hardware. R verifies and only then records the Φ commitment.
13. Erase — T wipes PII, live face, and QR bytes. Returns a handle. sk_IdR is
    recomputable later by re-scan + re-derive; it is NEVER stored.

## §3 Post-enrollment (per-service unlinkable identity)
For each service s, the user derives a Semaphore identity from (Φ, sk_IdR) and proves
membership with external nullifier = serviceId. nullifier_s = H(secret, serviceId).
Cross-service correlation is impossible without the user's secret. Reusing the same
service twice is detectable (same nullifier) → one identity per service.

## §4 Key derivation discipline
- OPRF input MUST be the stable, timestamp-stripped identifier (recovery-by-rescan works).
- The 17 timestamp bytes in the QR reference region are zeroed before hashing so re-scans
  are deterministic (same technique as Anon Aadhaar / Nova Aadhaar).
- Do NOT use the photo bytes as the seed (photo can change; it's for liveness only).
- Domain-separate every hash (distinct info/label strings).
- Zeroize all PII-derived intermediates after Φ and sk_IdR exist.

## §5 Crates → responsibilities
- aadhaar-qr   : parse Secure QR, verify UIDAI signature, extract fields/photo, stable digest
- liveness     : decode JP2 photo, accept live face, match
- palc         : HKDF-SHA3-512 + deterministic Kyber-1024 + commitment + Φ + zeroize
- voprf        : client blind/unblind + DLEQ verify (ristretto255)
- attestation  : TDX quote gen (configfs-tsm) + verify (dcap-rs) + simulation mode
- enrollment-tee: orchestrates §2 steps 1,4–13
- voprf-vault  : O — holds k, attested eval (Gate b/k server side)
- contracts    : Registry (novelty/dedup), GateZVerifier, NullifierRegistry
- circuits     : Gate Z (stub now)
- sdk          : enroll() / prove(serviceId) / verifyOnChain()
- app          : Sybil-resistant airdrop demo

## §6 Simulation flags
attestation runs in SIM mode by default (deterministic mock quotes). Real path behind
cargo feature "tdx". GateZVerifier has a sim mode that checks the mock attestation.
