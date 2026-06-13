/**
 * §3: per-service membership proofs. external nullifier (Semaphore "scope")
 * = serviceId; nullifier_s = H(secret, serviceId). Cross-service correlation
 * is impossible without the user's secret; same (user, service) twice yields
 * the SAME nullifier, which is what makes double-use detectable on-chain.
 */

import { keccak_256 } from "@noble/hashes/sha3";
import {
  generateProof,
  verifyProof,
  type Group,
  type Identity,
  type SemaphoreProof,
} from "@semaphore-protocol/core";

/**
 * Merkle depth the proofs are padded to (Groth16 artifacts are per-depth, so
 * this is pinned). Depth 10 covers groups up to 1024 members — demo scale.
 */
export const MERKLE_DEPTH = 10;

/**
 * Map a human-readable serviceId to the Semaphore scope / on-chain
 * `uint256 serviceId`: BigInt(keccak256(utf8(serviceId))) >> 8 (fits the
 * BN254 scalar field; same truncation convention Semaphore.sol uses).
 * Identity-critical (docs/DECISIONS.md): the NullifierRegistry key is this
 * value, so changing the mapping orphans every recorded nullifier.
 */
export function scopeOf(serviceId: string): bigint {
  const h = keccak_256(new TextEncoder().encode(serviceId));
  let v = 0n;
  for (const byte of h) v = (v << 8n) | BigInt(byte);
  return v >> 8n;
}

/** A §3 proof plus the values the registry consumes. */
export interface ServiceProof {
  proof: SemaphoreProof;
  /** scopeOf(serviceId) — the on-chain `uint256 serviceId`. */
  scope: bigint;
  /** nullifier_s — recorded on-chain as bytes32. */
  nullifier: bigint;
}

/** Prove membership of `group` for `serviceId`. `message` is the (public)
 *  signal the proof binds — e.g. a claim address; defaults to 0. */
export async function proveService(
  identity: Identity,
  group: Group,
  serviceId: string,
  message: bigint | string = 0n,
): Promise<ServiceProof> {
  const scope = scopeOf(serviceId);
  const proof = await generateProof(identity, group, message, scope, MERKLE_DEPTH);
  return { proof, scope, nullifier: BigInt(proof.nullifier) };
}

/** Off-chain Groth16 verification + consistency of the carried values. */
export async function verifyService(p: ServiceProof): Promise<boolean> {
  if (p.proof.merkleTreeDepth !== MERKLE_DEPTH) return false;
  if (BigInt(p.proof.scope) !== p.scope) return false;
  if (BigInt(p.proof.nullifier) !== p.nullifier) return false;
  return verifyProof(p.proof);
}

/** Field element → the bytes32 form NullifierRegistry stores. */
export function nullifierBytes32(n: bigint): `0x${string}` {
  if (n < 0n || n >= 1n << 256n) throw new Error("nullifier out of uint256 range");
  return `0x${n.toString(16).padStart(64, "0")}`;
}
