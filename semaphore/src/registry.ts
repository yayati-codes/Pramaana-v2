/**
 * Client for contracts/src/NullifierRegistry.sol: the on-chain double-use
 * ledger. The Groth16 membership proof is verified OFF-chain here before the
 * nullifier is recorded ON-chain (decision + on-chain-verifier hardening
 * path: docs/DECISIONS.md).
 */

import { Contract, type ContractRunner, type TransactionReceipt } from "ethers";
import { nullifierBytes32, verifyService, type ServiceProof } from "./proof.js";

export const NULLIFIER_REGISTRY_ABI = [
  "function spend(uint256 serviceId, bytes32 nullifier)",
  "function spent(uint256 serviceId, bytes32 nullifier) view returns (bool)",
  "event NullifierSpent(uint256 indexed serviceId, bytes32 indexed nullifier)",
  "error NullifierAlreadySpent(uint256 serviceId, bytes32 nullifier)",
] as const;

export class NullifierRegistryClient {
  readonly contract: Contract;

  constructor(address: string, runner: ContractRunner) {
    this.contract = new Contract(address, NULLIFIER_REGISTRY_ABI, runner);
  }

  async isSpent(scope: bigint, nullifier: bigint): Promise<boolean> {
    return this.contract.spent(scope, nullifierBytes32(nullifier));
  }

  /**
   * Verify the Semaphore proof off-chain, then record its nullifier.
   * Rejects locally on an invalid proof; reverts on-chain with
   * `NullifierAlreadySpent` on double-use within a service (§3: one
   * identity per service).
   */
  async checkAndSpend(p: ServiceProof): Promise<TransactionReceipt> {
    if (!(await verifyService(p))) {
      throw new Error("invalid Semaphore membership proof");
    }
    try {
      const tx = await this.contract.spend(p.scope, nullifierBytes32(p.nullifier));
      return await tx.wait();
    } catch (e) {
      // ethers does not decode custom errors raised during gas estimation;
      // surface the contract's revert (e.g. NullifierAlreadySpent) by name.
      const data = (e as { data?: unknown }).data;
      if (typeof data === "string") {
        const parsed = this.contract.interface.parseError(data);
        if (parsed) {
          throw new Error(`${parsed.name}(${parsed.args.map(String).join(", ")})`, { cause: e });
        }
      }
      throw e;
    }
  }
}
