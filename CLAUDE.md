# Pramaana — Agent Context (read this first, every session)

Pramaana is a post-quantum, self-sovereign identity protocol. It provides
anonymous-but-verified identity via a drop-in SDK, with structural unlinkability
across services enforced by cryptography, not policy. Beachhead: Sybil resistance for
crypto-native use cases (airdrops, quadratic funding, DAO governance).

It implements the enrollment step of the ASC/U2SSO framework (IACR ePrint 2025/618)
with a concrete, post-quantum, Sybil-resistant construction.

## The one-paragraph mental model
A user proves real-world uniqueness ONCE, inside a trusted enclave, using a
government-signed credential (here: the Aadhaar Secure QR). The enclave derives a
master identity Φ from that credential through an issuer-unknown secret (a VOPRF),
wraps it in a post-quantum lattice commitment (Kyber-1024), registers Φ's commitment
on-chain, and ERASES all PII. Afterwards the user derives a DIFFERENT unlinkable
pseudonym (nullifier) for every service via Semaphore. No party except the user can
correlate identities across services — structurally impossible, unlike OAuth/SSO.

## Non-negotiables
- PII is touched once, never stored, non-recoverable from the commitment.
- The VOPRF is load-bearing: the credential issuer (UIDAI) knows the full QR contents,
  so any nullifier that is a deterministic function of QR data + public salt is
  issuer-de-anonymizable. The issuer-unknown OPRF key k is the ONLY thing preventing
  trivial de-anon. Never make the seed a plain hash of QR fields.
- All enrollment TEE gates are present (Gate 0/b/k/Z). Liveness is present.
- The Aadhaar Secure QR REPLACES the ePassport NFC read. Everything else is identical.
  Enrollment is signature-verified, never OCR.
- Post-quantum claim is scoped to the IdR/registry-at-rest layer only. Do not claim
  end-to-end PQ (Anon-Aadhaar-style RSA verify + Groth16 are classical).

## Read next
docs/ARCHITECTURE.md (canonical spec), docs/THREAT_MODEL.md, docs/PROGRESS.md.
