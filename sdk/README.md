# @pramaana/sdk

Anonymous-but-verified identity in three calls. Enrollment runs ONCE inside an
attested TEE (Gate 0 verified client-side before any PII is sent); afterwards every
service gets a DIFFERENT unlinkable pseudonym, with double-use blocked on-chain.

```ts
import { Pramaana } from "@pramaana/sdk";

const pramaana = new Pramaana({
  teeUrl: "http://127.0.0.1:9966",            // tee-server (sim) or the TDX CVM
  rpcUrl: "http://127.0.0.1:8545",            // anvil / your chain
  nullifierRegistryAddress: "0x...",          // deployed NullifierRegistry
});

const { qrNumeric, frames } = await pramaana.fixture();             // sim-only demo QR
await pramaana.enroll(qrNumeric, { frames, capturedAtMs: Date.now() });
const proof = await pramaana.prove("service-A");                    // unlinkable per service
console.log(await pramaana.verifyOnChain(proof));                   // true — and after
await pramaana.claim(proof);                                        // claim() it's spent
```

- `enroll(qr, liveness)` — §2: Gate 0 attested handshake, UIDAI-signature
  verification, in-enclave face match, VOPRF (issuer-unknown key), post-quantum
  commitment, dedup (one human → one identity), PII erasure. The client receives
  (Φ, sk_IdR) and keeps them in memory only.
- `prove(serviceId)` — §3: Semaphore membership proof; `nullifier = H(secret,
  serviceId)`. Proofs for different services share NO user-derivable value.
- `verifyOnChain(proof)` — Groth16 verification + nullifier-unspent check against
  `NullifierRegistry`.
- `claim(proof)` — consumes the nullifier on-chain; a second claim reverts
  `NullifierAlreadySpent`.

Run the sim backend with `cargo run -p enrollment-tee --features sim-fixture --bin
tee-server` (env: `TEE_ADDR`, `VAULT_URL`). `fixture()` exists only in sim mode.
