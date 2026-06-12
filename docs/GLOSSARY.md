# Glossary

- **Φ (Phi)** — The master identity: Φ = H(C_commit), the hash of the post-quantum
  lattice commitment produced by PALC. Registered on-chain once per person; never
  reveals PII and is the root from which all per-service identities derive.

- **PALC** — Post-quantum Anonymous Lattice Commitment. The derivation in §2 step 10:
  HKDF-SHA3-512 stretches the OPRF output into a seed, Kyber-1024 keygen is run
  deterministically from that seed, and C_commit = pk_IdR ‖ Kyber1024.Enc(pk_IdR,
  H(seed)). Hiding/binding rests on lattice (ML-KEM) assumptions, hence the
  registry-at-rest post-quantum claim.

- **VOPRF / DLEQ** — Verifiable Oblivious Pseudorandom Function. The client (here: the
  enrollment TEE) blinds an input; the vault evaluates it under secret key k without
  learning the input; the client unblinds. The **DLEQ proof** (discrete-log equality)
  ships with each evaluation so the client can verify the vault used the committed k
  rather than a per-user key (which would be a linking attack). Instantiated over
  ristretto255.

- **Nullifier** — A per-service pseudonym: nullifier_s = H(secret, serviceId). Unlinkable
  across services without the user's secret; deterministic within a service, so a second
  use of the same service is detected (Sybil block) rather than minting a new identity.

- **RA-TLS** — Remote-Attestation TLS. A TLS channel whose handshake embeds an
  attestation quote with report_data binding the ephemeral TLS key, so the client knows
  it terminates *inside* a specific reviewed enclave, not merely at a server that owns a
  certificate.

- **TDX** — Intel Trust Domain Extensions. Confidential-VM technology isolating guest
  memory and state from the host/hypervisor, with hardware-rooted attestation quotes.
  Both T (enrollment TEE) and O (VOPRF vault) are TDX CVMs.

- **Gate 0 / b / k / Z** — The four enrollment attestation gates (§2):
  - **Gate 0**: client verifies T's RA-TLS quote before sending anything.
  - **Gate b**: vault verifies T's quote, bound to the blinded input, before evaluating.
  - **Gate k**: T verifies the vault's proof that k is sealed in a genuine TDX CVM.
  - **Gate Z**: ZK proof that C_commit came from reviewed code on approved hardware,
    verified on-chain before the Φ commitment is recorded.

- **Semaphore** — A zero-knowledge group-membership protocol. Post-enrollment, the user
  derives a Semaphore identity from (Φ, sk_IdR) and proves membership in the registry
  group with an external nullifier per service.

- **ML-KEM / Kyber** — The NIST-standardized lattice KEM (FIPS 203); Kyber-1024 is the
  highest security level. Used deterministically inside PALC for the post-quantum
  commitment; its keypair (pk_IdR, sk_IdR) is recomputable from the seed and never stored.

- **HKDF** — HMAC-based key derivation function (here over SHA3-512). Stretches
  oprf_output ‖ H(stable_id) into the PALC seed with a domain-separating info string
  ("pramaana-v1").

- **Secure QR** — The UIDAI-signed QR code on Aadhaar letters/e-Aadhaar: an
  RSA-2048/SHA-256 signed blob containing demographic reference fields and a JPEG2000
  photo. It is the government-signed credential consumed at enrollment (replacing the
  ePassport NFC read) — a bearer credential; see THREAT_MODEL.md (a).
