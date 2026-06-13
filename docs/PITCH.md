# Pramaana — Pitch

**Anonymous-but-verified identity. Sybil resistance without surveillance.**

Pramaana lets a user prove real-world uniqueness ONCE — inside an attested enclave,
from a government-signed credential — then derive a *different* unlinkable pseudonym for
every service. One human, one identity, one claim per service; yet no party (not even the
credential issuer) can correlate that human across services. The unlinkability is
structural — enforced by cryptography, not policy.

Beachhead: Sybil resistance for crypto-native use cases — airdrops, quadratic funding,
DAO governance.

---

## The 3-minute flow

1. **Enroll once.** The client asks the enrollment TEE to start and **verifies its
   attestation quote before sending anything** (Gate 0). It then scans the Aadhaar Secure
   QR and a live face capture. Inside the enclave: the UIDAI RSA signature is verified
   (never OCR), the live face is matched to the QR photo, a stable timestamp-stripped
   identifier is **blinded** and sent to a separate vault that evaluates a **VOPRF** under
   an issuer-unknown key `k` (Gate b/k), the result is wrapped in a **post-quantum
   Kyber-1024 commitment** → master identity **Φ**, a per-person **dedup tag** blocks a
   second enrollment, and **all PII is erased**. The user walks away holding (Φ, sk_IdR);
   the TEE keeps nothing.
2. **Claim an airdrop.** For service *s*, the user derives a Semaphore identity from
   (Φ, sk_IdR) and produces a membership proof with external nullifier = *s*. The claim
   spends `nullifier_s` on-chain.
3. **Claim again → blocked.** The same human re-claiming the same airdrop reproduces the
   same nullifier; the on-chain registry reverts. One human, one claim.
4. **Second service → uncorrelatable.** The same human claims a *different* airdrop. Its
   nullifier shares no derivable value with the first — the two services cannot tell
   they served the same person.

Run it: **`make demo`** (headless, asserts the whole thing) or
**`pnpm --filter @pramaana/app demo`** (interactive browser click-through).

---

## What's real vs. simulated (be honest)

| Component | Demo state |
|---|---|
| Aadhaar Secure QR parse + UIDAI RSA/SHA-256 verify | **Real** |
| Liveness / face-match against the QR photo | **Real** (pluggable: sim threshold or ONNX) |
| PALC (HKDF-SHA3-512 → ML-KEM-1024 → Φ) | **Real** |
| VOPRF (blind / eval / unblind + DLEQ) | **Real** (RFC 9497, ristretto255) |
| Semaphore per-service nullifiers | **Real** (Groth16 / BN254) |
| Registry + NullifierRegistry contracts | **Real** (Foundry / anvil) |
| Drop-in SDK + demo app | **Real** |
| TDX quote gen / verify (Gate 0/b/k) | **Sim** — three interchangeable backends, same gate logic; real path behind `tdx` / `dstack` features (deploy to Phala Cloud, no flag changes) |
| Gate Z (DCAP-quote-in-ZK) | **Sim stub verifier** — checks the mock attestation; the DCAP-in-ZK circuit is post-hackathon |

Honest footnotes:
- On-chain Φ registration via `Registry.sol` (novelty + dedup + Gate Z) is **tested in
  Foundry** but not yet wired into the SDK enroll path; the SDK currently exercises the
  on-chain `NullifierRegistry` (double-use ledger). Wiring `Registry.sol` in (and pinning
  the Φ64→bytes32 mapping) is the next integration step.
- The post-quantum claim is **scoped to the IdR / registry-at-rest layer** (PALC's
  Kyber-1024 commitment). Anon-Aadhaar-style RSA verification and Groth16 proving are
  classical — we do not claim end-to-end PQ.
- The Aadhaar QR is a **bearer** credential (no hardware clone-resistance like a passport
  chip). Uniqueness holds at the nullifier layer (one Aadhaar → one identity even if the
  QR is shared); liveness binds the live face to the QR photo, which is the anti-rental
  defense. The ePassport NFC read is a drop-in enrollment adapter later.

---

## Two headline claims, each with a one-line proof

**1. Structural unlinkability — services cannot correlate the same human.**
A user's per-service pseudonyms share no derivable value; correlation is impossible
without the user's secret. `nullifier_s = H(secret, serviceId)`, and the only value two
proofs share is the group-wide Merkle root (which every member shares).
*Proof:* `semaphore/test/unlinkability.test.ts` asserts two services' nullifiers/scopes
share nothing and that a second user carries the same root; the same assertion runs in
`sdk/test/e2e.test.ts`, `app/test/app.e2e.test.ts`, and `make demo`.

**2. Issuer de-anonymization blocked by the VOPRF.**
UIDAI knows the full QR contents, so any identifier that is a deterministic function of
QR data + public salt would be trivially de-anonymizable by the issuer. Pramaana derives
Φ **through the issuer-unknown OPRF key `k`** (the VOPRF output is in PALC's HKDF IKM),
and the on-chain dedup tag is derived **through Φ** — never from QR fields. So the
issuer, despite knowing everything on the QR, cannot compute Φ or the on-chain tag.
*Proof:* the dedup-tag derivation (`SHA3-256("pramaana-dedup-v1" ‖ Φ)`) in
`crates/enrollment-tee/src/lib.rs`, recorded in `docs/DECISIONS.md`; the non-negotiable
in `CLAUDE.md`; threat `(b)` in `docs/THREAT_MODEL.md`. The VOPRF's DLEQ proof
(`crates/voprf`) pins evaluations to the committed key so the vault cannot use a
per-user key to re-introduce a backdoor.

---

## Why it's different from OAuth / SSO

OAuth gives you "log in with X," and X sees every place you log in. Pramaana gives you a
*mathematically separate* identity per service that even the credential issuer cannot
join up. Same convenience (a drop-in SDK: `enroll` / `prove` / `verifyOnChain`),
opposite privacy posture — unlinkability by construction, not by a privacy policy.
