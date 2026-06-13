/**
 * @pramaana/sdk — anonymous-but-verified identity in three calls (§5).
 *
 * enroll(qr, liveness)  → drives the §2 enrollment-TEE flow (Gate 0 first).
 * prove(serviceId)      → per-service unlinkable Semaphore proof (§3).
 * verifyOnChain(proof)  → proof valid AND nullifier unspent on-chain.
 *
 * All gate/TEE complexity stays behind these calls.
 */

import { hexToBytes } from "@noble/hashes/utils";
import {
  deriveIdentity,
  Group,
  NullifierRegistryClient,
  proveService,
  verifyService,
  type ServiceProof,
} from "@pramaana/semaphore";
import { JsonRpcProvider, type ContractRunner } from "ethers";
import { TeeClient, type CaptureFrame, type LivenessCapture } from "./tee.js";

export {
  AttestationError,
  SIM_MEASUREMENT,
  verifyReportDataBinding,
  verifySimQuote,
} from "./attestation.js";
export { TeeClient, TeeError } from "./tee.js";
export type { CaptureFrame, LivenessCapture, TeeEnrollment } from "./tee.js";
export type { ServiceProof };

export interface PramaanaConfig {
  /** Enrollment TEE base URL (T). */
  teeUrl: string;
  /** JSON-RPC endpoint for on-chain checks (or pass `signer`). */
  rpcUrl?: string;
  /** ethers runner (Wallet/Signer for claim(); Provider suffices to verify). */
  signer?: ContractRunner;
  /** Deployed NullifierRegistry address. */
  nullifierRegistryAddress?: string;
  /**
   * Other enrolled identity commitments forming the Semaphore group. The
   * caller's own commitment is appended automatically. (Demo-scale group
   * management; the registry-backed group arrives with the e2e wiring.)
   */
  groupMembers?: (bigint | string)[];
  /** Gate 0 appraisal policy override (defaults to the sim measurement). */
  allowedMeasurements?: Uint8Array[];
}

/** §2 step 13 result: public data only (sk_IdR stays inside the client). */
export interface EnrollmentHandle {
  /** Φ = SHA3-512(C_commit), hex. */
  phi: string;
  dedupTag: string;
  /** True when dedup returned the EXISTING identity (no second mint). */
  alreadyEnrolled: boolean;
}

export class Pramaana {
  readonly #tee: TeeClient;
  readonly #config: PramaanaConfig;
  #registry?: NullifierRegistryClient;
  #session?: { phi: Uint8Array; skIdr: Uint8Array };

  constructor(config: PramaanaConfig) {
    this.#config = config;
    this.#tee = new TeeClient(config.teeUrl, config.allowedMeasurements);
    if (config.nullifierRegistryAddress) {
      const runner =
        config.signer ?? (config.rpcUrl ? new JsonRpcProvider(config.rpcUrl) : undefined);
      if (runner) {
        this.#registry = new NullifierRegistryClient(config.nullifierRegistryAddress, runner);
      }
    }
  }

  /**
   * §2 enrollment: Gate 0 attested handshake (verifying T's quote BEFORE any
   * PII is sent), then QR + liveness over the attested channel. On success
   * the client holds (Φ, sk_IdR) in memory for prove(); T has erased all PII
   * and persists nothing.
   */
  async enroll(qrNumeric: string, liveness: LivenessCapture): Promise<EnrollmentHandle> {
    const { livenessNonce } = await this.#tee.handshake();
    const res = await this.#tee.enroll(qrNumeric, liveness, livenessNonce);

    this.#session?.skIdr.fill(0); // overwrite any previous session secret
    this.#session = { phi: hexToBytes(res.phi), skIdr: res.skIdr };
    return { phi: res.phi, dedupTag: res.dedupTag, alreadyEnrolled: res.alreadyEnrolled };
  }

  /** §3: unlinkable per-service proof + nullifier. Requires enroll() first. */
  async prove(serviceId: string): Promise<ServiceProof> {
    const session = this.#session;
    if (!session) {
      throw new Error("prove() requires a successful enroll() in this session");
    }
    const identity = deriveIdentity(session.phi, session.skIdr);
    const members = (this.#config.groupMembers ?? []).map(BigInt);
    if (!members.includes(identity.commitment)) {
      members.push(identity.commitment);
    }
    return proveService(identity, new Group(members), serviceId);
  }

  /** Proof valid (off-chain Groth16) AND nullifier unspent on-chain. */
  async verifyOnChain(proof: ServiceProof): Promise<boolean> {
    if (!(await verifyService(proof))) {
      return false;
    }
    return !(await this.#requireRegistry().isSpent(proof.scope, proof.nullifier));
  }

  /**
   * Consume the nullifier on-chain (one identity per service): verifies the
   * proof off-chain, then spends. Reverts `NullifierAlreadySpent(...)` on
   * double-use. This is what an airdrop-style claim calls.
   */
  async claim(proof: ServiceProof): Promise<void> {
    await this.#requireRegistry().checkAndSpend(proof);
  }

  /** SIM-ONLY demo helper: synthetic signed QR + capture from tee-server. */
  async fixture(): Promise<{ qrNumeric: string; frames: CaptureFrame[] }> {
    return this.#tee.fixture();
  }

  #requireRegistry(): NullifierRegistryClient {
    if (!this.#registry) {
      throw new Error(
        "on-chain checks need nullifierRegistryAddress plus rpcUrl or signer in PramaanaConfig",
      );
    }
    return this.#registry;
  }
}
