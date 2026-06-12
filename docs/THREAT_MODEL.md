# Pramaana Threat Model

This document captures the threats specific to the Aadhaar variant. Read
ARCHITECTURE.md first; gate numbers refer to its §2.

## (a) The Aadhaar Secure QR is a BEARER credential

Unlike an ePassport chip, the Secure QR has **no hardware clone-resistance**: it is a
static, signed blob. Anyone holding the bytes holds the credential — active
authentication, chip binding, and anti-cloning do not exist here.

What this does and does not break:

- **Uniqueness is preserved at the nullifier layer.** The stable identifier (and
  therefore Φ and every per-service nullifier) is a deterministic function of one
  Aadhaar's reference fields. One Aadhaar → one identity, even if the QR bytes are
  shared among many people. A cloned QR cannot mint a second identity; it can only
  re-derive the same one.
- **The Sybil cost is "acquire N distinct signed QRs."** The realistic attack is a
  rental market: paying N real Aadhaar holders for their QR codes to enroll N
  identities controlled by one party.
- **Mitigation: liveness binds the live face to the QR photo at enrollment** (§2 step
  5, inside the enclave). A renter must also produce a live face matching the QR's
  embedded photo, raising the rental attack from "buy bytes" to "recruit cooperating
  humans per enrollment" — a per-identity, in-person cost.

## (b) Issuer de-anonymization (UIDAI)

UIDAI signs the QR and therefore **knows its full contents** for every holder. Any
nullifier that is a deterministic function of QR data plus public salts is trivially
de-anonymizable by the issuer: UIDAI could enumerate its database, recompute every
nullifier, and unmask users.

**The VOPRF with issuer-unknown key k is the sole structural blocker.** The stable
identifier is blinded before evaluation (the vault never sees it), and the output is
unpredictable to anyone without k — including UIDAI. Consequences:

- The seed must NEVER degrade into a plain hash of QR fields (see CLAUDE.md
  non-negotiables).
- k's secrecy and its confinement to an attested TDX CVM (Gates b/k) carry the entire
  unlinkability claim against the issuer. Compromise of k reduces privacy to the
  Anon-Aadhaar baseline (issuer-enumerable), though Sybil resistance survives.

## (c) TDX threat model

The enrollment TEE and the VOPRF vault run in Intel TDX confidential VMs.

- **PPID-binding closes hardware-identity gaps**: quotes are bound to a specific
  platform identity, so an attacker cannot substitute an unapproved machine or relay
  quotes from elsewhere in the fleet.
- **Not covered**: side-channel attacks (architectural and microarchitectural leakage)
  and physical attacks on the host (bus interposition, voltage/clock fault injection).
  An adversary with physical possession of the platform, or a future side-channel
  against TDX, is outside this model. We rely on Intel's TCB recovery process and
  appraisal-policy updates to react.

## (d) Attestation gates actions, not computation on public data

Attestation (Gates 0/b/k/Z) is used to gate **actions whose inputs or effects must be
trusted**: receiving PII, evaluating the VOPRF, and registering commitments on-chain.
It is NOT used to protect computation over public data — anyone may recompute hashes,
verify proofs, or read the registry. Designs must not assume attestation makes public
computation secret; it only proves that a *specific reviewed binary on approved
hardware* performed a privileged action.
