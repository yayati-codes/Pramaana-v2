/**
 * §3: the user derives a Semaphore identity deterministically from
 * (Φ, sk_IdR). Both values come out of PALC (§2 step 10); the user recovers
 * them by re-scan + re-derive, so the same person always lands on the same
 * Semaphore identity — and therefore the same per-service nullifiers.
 */

import { sha3_256 } from "@noble/hashes/sha3";
import { Identity } from "@semaphore-protocol/core";

/** Φ = SHA3-512(C_commit) — palc output size. */
export const PHI_LEN = 64;
/** sk_IdR = ML-KEM-1024 decapsulation key — palc output size. */
export const SK_IDR_LEN = 3168;

/** Identity-critical (see docs/DECISIONS.md): changing this domain or the
 *  framing below re-keys every user's Semaphore identity. */
const IDENTITY_DOMAIN = "pramaana-semaphore-identity-v1";

function u16le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * secret = SHA3-256(domain ‖ u16_le(64) ‖ Φ ‖ u16_le(3168) ‖ sk_IdR),
 * used as the Semaphore (EdDSA) private key. Deterministic: same (Φ, sk_IdR)
 * → same identity commitment.
 *
 * sk_IdR is REQUIRED, not optional hardening: Φ is registered on-chain and
 * public, so a secret derived from Φ alone would let anyone mint this user's
 * nullifiers. Lengths are validated to exactly the palc sizes.
 */
export function deriveIdentity(phi: Uint8Array, skIdr: Uint8Array): Identity {
  if (phi.length !== PHI_LEN) {
    throw new Error(`phi must be ${PHI_LEN} bytes (SHA3-512(C_commit)), got ${phi.length}`);
  }
  if (skIdr.length !== SK_IDR_LEN) {
    throw new Error(`skIdr must be ${SK_IDR_LEN} bytes (ML-KEM-1024 dk), got ${skIdr.length}`);
  }
  const secret = sha3_256(
    concatBytes(
      new TextEncoder().encode(IDENTITY_DOMAIN),
      u16le(phi.length),
      phi,
      u16le(skIdr.length),
      skIdr,
    ),
  );
  return new Identity(secret);
}
