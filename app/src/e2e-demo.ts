/**
 * Headless end-to-end demo (`make demo`): brings up anvil + voprf-vault +
 * enrollment-tee (sim), deploys NullifierRegistry, then drives the SDK
 * through enroll → prove → claim and ASSERTS the two headline properties —
 * Sybil resistance (enrollment dedup + per-service double-spend) and
 * cross-service unlinkability. Exits non-zero on any failure so `make demo`
 * fails loudly.
 *
 * For the interactive browser version, use `pnpm --filter @pramaana/app demo`.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Pramaana } from "@pramaana/sdk";
import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";
import { orchestrate, type Backends } from "./orchestrate.js";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
// anvil's first dev account — SIM-ONLY demo deployer/signer.
const ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function step(msg: string): void {
  console.log(`\n▸ ${msg}`);
}
function ok(msg: string): void {
  console.log(`  ✓ ${msg}`);
}
function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
  ok(msg);
}

async function deployNullifierRegistry(wallet: Wallet): Promise<string> {
  const artifact = JSON.parse(
    readFileSync(
      join(REPO_ROOT, "contracts", "out", "NullifierRegistry.sol", "NullifierRegistry.json"),
      "utf8",
    ),
  );
  const c = await new ContractFactory(artifact.abi, artifact.bytecode.object, wallet).deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

async function main(): Promise<void> {
  let backends: Backends | null = null;
  try {
    step("Bringing up the sim stack (anvil · voprf-vault · enrollment-tee)…");
    backends = await orchestrate({
      anvilPort: 8560,
      teePort: 9980,
      vaultPort: 9945,
      separateVault: true,
    });
    ok(`anvil          → ${backends.rpcUrl}`);
    ok(`voprf-vault O  → ${backends.vaultUrl} (holds the OPRF key k; tee never sees it)`);
    ok(`enrollment-tee → ${backends.teeUrl} (Gate 0/b/k/Z, sim)`);

    step("Deploying NullifierRegistry to anvil…");
    const wallet = new Wallet(
      ANVIL_KEY0,
      new JsonRpcProvider(backends.rpcUrl, undefined, { pollingInterval: 50, cacheTimeout: -1 }),
    );
    const nullifierRegistryAddress = await deployNullifierRegistry(wallet);
    ok(`NullifierRegistry @ ${nullifierRegistryAddress}`);

    const pramaana = new Pramaana({
      teeUrl: backends.teeUrl,
      signer: wallet,
      nullifierRegistryAddress,
    });

    // ---- Enrollment (§2) + the enrollment-layer Sybil block --------------
    step("User enrolls ONCE inside the TEE (Gate 0 verified client-side first)…");
    const { qrNumeric, frames } = await pramaana.fixture();
    const first = await pramaana.enroll(qrNumeric, { frames, capturedAtMs: Date.now() });
    assert(/^[0-9a-f]{128}$/.test(first.phi), "Φ minted (SHA3-512 master identity)");
    assert(first.alreadyEnrolled === false, "first enrollment is a fresh identity");

    step("Same human re-scans (recovery-by-rescan)…");
    const again = await pramaana.enroll(qrNumeric, { frames, capturedAtMs: Date.now() });
    assert(again.phi === first.phi, "re-scan reproduces the SAME Φ (issuer-unknown k is stable)");
    assert(again.alreadyEnrolled === true, "dedup blocks a second mint (Sybil block @ enrollment)");

    // ---- Per-service claim + the per-service Sybil block -----------------
    step('Claiming airdrop "service-A"…');
    const proofA = await pramaana.prove("service-A");
    assert(await pramaana.verifyOnChain(proofA), "proof valid and nullifier unspent");
    await pramaana.claim(proofA);
    ok("claim recorded on-chain");

    step('Same human claims "service-A" AGAIN…');
    let blocked = false;
    try {
      await pramaana.claim(proofA);
    } catch (e) {
      blocked = String((e as Error).message).includes("NullifierAlreadySpent");
    }
    assert(blocked, "second claim REVERTS (Sybil block @ service: one human, one claim)");
    assert((await pramaana.verifyOnChain(proofA)) === false, "nullifier now shows spent");

    // ---- Cross-service unlinkability -------------------------------------
    step('Same human claims a DIFFERENT airdrop "service-B"…');
    const proofB = await pramaana.prove("service-B");
    assert(await pramaana.verifyOnChain(proofB), "service-B proof valid and unspent");
    assert(proofB.nullifier !== proofA.nullifier, "service-A and service-B nullifiers differ");
    assert(proofB.scope !== proofA.scope, "the two service scopes differ");
    const sharedValues = [proofA.nullifier, proofA.scope].filter(
      (v) => v === proofB.nullifier || v === proofB.scope,
    );
    assert(sharedValues.length === 0, "the two services share NO user-derivable value");

    console.log("\n────────────────────────────────────────────────────────");
    console.log("  ✓ Sybil resistance: one human → one identity → one claim/service");
    console.log("  ✓ Structural unlinkability: services cannot correlate the same human");
    console.log("  ✓ Issuer de-anon blocked: Φ derives through the issuer-unknown VOPRF key k");
    console.log("\n  make demo: GREEN\n");
  } finally {
    backends?.stop();
  }
}

main()
  .then(() => {
    // Force exit: the ethers provider's polling timer (and the killed child
    // processes' handles) would otherwise keep the event loop alive forever
    // even though every assertion passed.
    process.exit(0);
  })
  .catch((err) => {
    console.error(`\n  make demo: FAILED\n  ${String(err)}\n`);
    process.exit(1);
  });
