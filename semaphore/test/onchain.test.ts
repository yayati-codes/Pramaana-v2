/**
 * DoD: same user, same serviceId, twice → the second proof is rejected
 * ON-CHAIN (NullifierAlreadySpent). Boots a local anvil, deploys
 * NullifierRegistry from the forge artifact, and drives it through
 * NullifierRegistryClient with REAL Semaphore proofs.
 */

import { execSync, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Group } from "@semaphore-protocol/core";
import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deriveIdentity } from "../src/identity.js";
import { proveService, type ServiceProof } from "../src/proof.js";
import { NullifierRegistryClient } from "../src/registry.js";
import { userA } from "./fixtures.js";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const FOUNDRY_BIN = join(process.env.HOME ?? "", ".foundry", "bin");
const ANVIL_PORT = 8945;
// anvil's first well-known dev account.
const ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

let anvil: ChildProcess;
let client: NullifierRegistryClient;
let proofA: ServiceProof;
let proofB: ServiceProof;

beforeAll(async () => {
  // Build the contract artifact, then boot the chain.
  execSync(`${join(FOUNDRY_BIN, "forge")} build --root ${join(REPO_ROOT, "contracts")}`, {
    stdio: "pipe",
  });
  anvil = spawn(join(FOUNDRY_BIN, "anvil"), ["--port", String(ANVIL_PORT), "--silent"], {
    stdio: "ignore",
  });

  const provider = new JsonRpcProvider(`http://127.0.0.1:${ANVIL_PORT}`, undefined, {
    pollingInterval: 50,
    // The double-spend test sends an IDENTICAL call right after the first
    // spend; ethers' default 250ms result cache would replay the first
    // estimateGas/getTransactionCount and mask the revert with a stale nonce.
    cacheTimeout: -1,
  });
  // Wait for the node to accept requests.
  for (let i = 0; ; i++) {
    try {
      await provider.getBlockNumber();
      break;
    } catch (e) {
      if (i > 100) throw e;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  const wallet = new Wallet(ANVIL_KEY0, provider);

  const artifact = JSON.parse(
    readFileSync(
      join(REPO_ROOT, "contracts", "out", "NullifierRegistry.sol", "NullifierRegistry.json"),
      "utf8",
    ),
  );
  const factory = new ContractFactory(artifact.abi, artifact.bytecode.object, wallet);
  const deployed = await factory.deploy();
  await deployed.waitForDeployment();
  client = new NullifierRegistryClient(await deployed.getAddress(), wallet);

  const identity = deriveIdentity(userA.phi, userA.skIdr);
  const group = new Group([identity.commitment]);
  proofA = await proveService(identity, group, "service-A");
  proofB = await proveService(identity, group, "service-B");
});

afterAll(() => {
  anvil?.kill();
});

describe("NullifierRegistry on-chain (§3 DoD)", () => {
  it("first claim for a service succeeds and is recorded", async () => {
    expect(await client.isSpent(proofA.scope, proofA.nullifier)).toBe(false);
    const receipt = await client.checkAndSpend(proofA);
    expect(receipt?.status).toBe(1);
    expect(await client.isSpent(proofA.scope, proofA.nullifier)).toBe(true);
  });

  it("same user, same service, twice → second spend REVERTS on-chain", async () => {
    let revertName = "";
    try {
      await client.checkAndSpend(proofA);
    } catch (e) {
      const err = e as { revert?: { name?: string }; message?: string };
      revertName = err.revert?.name ?? err.message ?? "";
    }
    expect(revertName).toContain("NullifierAlreadySpent");
  });

  it("same user, DIFFERENT service → independent claim succeeds", async () => {
    const receipt = await client.checkAndSpend(proofB);
    expect(receipt?.status).toBe(1);
    expect(await client.isSpent(proofB.scope, proofB.nullifier)).toBe(true);
  });

  it("an invalid proof never reaches the chain", async () => {
    const forged: ServiceProof = {
      ...proofB,
      nullifier: proofB.nullifier ^ 1n,
      proof: { ...proofB.proof, nullifier: (BigInt(proofB.proof.nullifier) ^ 1n).toString() },
    };
    await expect(client.checkAndSpend(forged)).rejects.toThrow(
      /invalid Semaphore membership proof/,
    );
    expect(await client.isSpent(forged.scope, forged.nullifier)).toBe(false);
  });
});
