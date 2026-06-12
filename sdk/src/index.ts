/**
 * @pramaana/sdk — public API surface (ARCHITECTURE.md §5).
 * All three entry points are stubs until enrollment-tee/voprf-vault land.
 */

export class NotImplementedError extends Error {
  constructor(api: string) {
    super(`${api} is not implemented yet`);
    this.name = "NotImplementedError";
  }
}

/** Result of §2 enrollment, returned after the TEE erases all PII (step 13). */
export interface EnrollmentHandle {
  /** Φ = H(C_commit), hex-encoded. */
  phi: string;
  /** Opaque handle; sk_IdR is recomputable by re-scan + re-derive, never stored. */
  handle: string;
}

/** Per-service membership proof (§3). */
export interface ServiceProof {
  serviceId: string;
  /** nullifier_s = H(secret, serviceId), hex-encoded. */
  nullifier: string;
  /** Semaphore proof bytes. */
  proof: Uint8Array;
}

/** Run the §2 enrollment flow against an attested enrollment TEE (Gate 0 first). */
export async function enroll(): Promise<EnrollmentHandle> {
  throw new NotImplementedError("enroll()");
}

/** Derive the unlinkable per-service identity and prove registry membership (§3). */
export async function prove(serviceId: string): Promise<ServiceProof> {
  throw new NotImplementedError(`prove(${JSON.stringify(serviceId)})`);
}

/** Verify a service proof against Registry/NullifierRegistry on-chain. */
export async function verifyOnChain(proof: ServiceProof): Promise<boolean> {
  throw new NotImplementedError(`verifyOnChain(serviceId=${proof.serviceId})`);
}
