/**
 * @pramaana/semaphore — per-service unlinkable nullifiers (ARCHITECTURE.md §3).
 *
 * The SDK's prove(serviceId) is a thin wrapper over:
 *   deriveIdentity(Φ, sk_IdR) → proveService(identity, group, serviceId)
 *   → NullifierRegistryClient.checkAndSpend(proof)
 */

export { deriveIdentity, PHI_LEN, SK_IDR_LEN } from "./identity.js";
export {
  MERKLE_DEPTH,
  nullifierBytes32,
  proveService,
  scopeOf,
  verifyService,
  type ServiceProof,
} from "./proof.js";
export { NULLIFIER_REGISTRY_ABI, NullifierRegistryClient } from "./registry.js";

// Re-export the Semaphore primitives consumers need to build groups.
export { Group, Identity, type SemaphoreProof } from "@semaphore-protocol/core";
