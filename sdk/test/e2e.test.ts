/**
 * DoD: through the PUBLIC SDK API only — enroll against a real tee-server
 * (Rust, sim mode), prove for "service-A", verify on a local anvil; and
 * service-A vs service-B nullifiers are unlinkable.
 */

import { execSync, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pramaana, type ServiceProof } from "../src/index.js";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const FOUNDRY_BIN = join(process.env.HOME ?? "", ".foundry", "bin");
const ANVIL_PORT = 8946;
const TEE_PORT = 9967;
const ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

let anvil: ChildProcess;
let teeServer: ChildProcess;
let pramaana: Pramaana;

async function waitFor(probe: () => Promise<void>, what: string): Promise<void> {
  for (let i = 0; ; i++) {
    try {
      await probe();
      return;
    } catch (e) {
      if (i > 200) throw new Error(`${what} did not come up: ${e}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }
}

beforeAll(async () => {
  // Real Rust backend: build + spawn tee-server (in-process sim vault).
  execSync("cargo build -p enrollment-tee --features sim-fixture --bin tee-server", {
    cwd: REPO_ROOT,
    stdio: "pipe",
  });
  teeServer = spawn(join(REPO_ROOT, "target", "debug", "tee-server"), [], {
    env: { ...process.env, TEE_ADDR: `127.0.0.1:${TEE_PORT}` },
    stdio: "ignore",
  });

  // Chain: anvil + NullifierRegistry from the forge artifact.
  execSync(`${join(FOUNDRY_BIN, "forge")} build --root ${join(REPO_ROOT, "contracts")}`, {
    stdio: "pipe",
  });
  anvil = spawn(join(FOUNDRY_BIN, "anvil"), ["--port", String(ANVIL_PORT), "--silent"], {
    stdio: "ignore",
  });
  const provider = new JsonRpcProvider(`http://127.0.0.1:${ANVIL_PORT}`, undefined, {
    pollingInterval: 50,
    cacheTimeout: -1, // back-to-back identical calls in the double-claim test
  });
  await waitFor(async () => {
    await provider.getBlockNumber();
  }, "anvil");
  const wallet = new Wallet(ANVIL_KEY0, provider);
  const artifact = JSON.parse(
    readFileSync(
      join(REPO_ROOT, "contracts", "out", "NullifierRegistry.sol", "NullifierRegistry.json"),
      "utf8",
    ),
  );
  const deployed = await new ContractFactory(
    artifact.abi,
    artifact.bytecode.object,
    wallet,
  ).deploy();
  await deployed.waitForDeployment();

  await waitFor(async () => {
    const res = await fetch(`http://127.0.0.1:${TEE_PORT}/fixture`);
    if (!res.ok) throw new Error(String(res.status));
  }, "tee-server");

  pramaana = new Pramaana({
    teeUrl: `http://127.0.0.1:${TEE_PORT}`,
    signer: wallet,
    nullifierRegistryAddress: await deployed.getAddress(),
  });
});

afterAll(() => {
  teeServer?.kill();
  anvil?.kill();
});

describe("SDK end-to-end (sim TEE + anvil)", () => {
  let proofA: ServiceProof;

  it("enrolls via the real §2 flow and recovers the same Φ on re-scan", async () => {
    const { qrNumeric, frames } = await pramaana.fixture();
    const first = await pramaana.enroll(qrNumeric, { frames, capturedAtMs: Date.now() });
    expect(first.phi).toMatch(/^[0-9a-f]{128}$/); // Φ = SHA3-512
    expect(first.alreadyEnrolled).toBe(false);

    // Same person re-enrolls (fresh QR scan): same Φ, dedup blocks a 2nd mint.
    const again = await pramaana.enroll(qrNumeric, { frames, capturedAtMs: Date.now() });
    expect(again.phi).toBe(first.phi);
    expect(again.alreadyEnrolled).toBe(true);
  });

  it("proves for service-A and verifies on-chain; claim is one-shot", async () => {
    proofA = await pramaana.prove("service-A");
    expect(await pramaana.verifyOnChain(proofA)).toBe(true);

    await pramaana.claim(proofA);
    await expect(pramaana.claim(proofA)).rejects.toThrow(/NullifierAlreadySpent/);
    // Spent now → no longer "valid and unspent".
    expect(await pramaana.verifyOnChain(proofA)).toBe(false);
  });

  it("DoD: service-A and service-B nullifiers are unlinkable", async () => {
    const proofB = await pramaana.prove("service-B");
    expect(await pramaana.verifyOnChain(proofB)).toBe(true);

    // Different nullifier, different scope; no user-derivable public value
    // is shared between what the two services see (the merkle root is
    // group-wide, not user-specific — semaphore package tests pin that).
    expect(proofB.nullifier).not.toBe(proofA.nullifier);
    expect(proofB.scope).not.toBe(proofA.scope);
    const seenByA = [proofA.nullifier, proofA.scope];
    const seenByB = [proofB.nullifier, proofB.scope];
    expect(seenByA.filter((v) => seenByB.includes(v))).toHaveLength(0);
  });

  it("rejects proving without an enrolled session", async () => {
    const fresh = new Pramaana({ teeUrl: `http://127.0.0.1:${TEE_PORT}` });
    await expect(fresh.prove("service-A")).rejects.toThrow(/enroll/);
  });
});
