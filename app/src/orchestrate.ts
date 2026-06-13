/**
 * Brings up the sim backends the demo needs: a local anvil chain and the
 * Rust enrollment backend. By default the tee-server hosts an in-process
 * vault (simplest, used by the e2e tests). With `separateVault: true` the
 * voprf-vault runs as its OWN process and the tee talks to it over VAULT_URL
 * — the honest key-custody split O holds k in its own service (used by
 * `make demo`). Mirrors the harness in sdk/test/e2e.test.ts.
 */

import { execSync, spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonRpcProvider } from "ethers";

// app/dist/orchestrate.js → repo root is three levels up; app/src too.
const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const FOUNDRY_BIN = join(process.env.HOME ?? "", ".foundry", "bin");

export interface Backends {
  rpcUrl: string;
  teeUrl: string;
  /** Set only when `separateVault` was requested. */
  vaultUrl?: string;
  stop: () => void;
}

export interface OrchestrateOptions {
  anvilPort?: number;
  teePort?: number;
  vaultPort?: number;
  /** Run voprf-vault as a separate process (key-custody split). */
  separateVault?: boolean;
}

async function waitFor(probe: () => Promise<void>, what: string): Promise<void> {
  for (let i = 0; ; i++) {
    try {
      await probe();
      return;
    } catch (e) {
      if (i > 200) throw new Error(`${what} did not come up: ${String(e)}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }
}

export async function orchestrate(opts: OrchestrateOptions = {}): Promise<Backends> {
  const anvilPort = opts.anvilPort ?? 8550;
  const teePort = opts.teePort ?? 9970;
  const vaultPort = opts.vaultPort ?? 9944;

  // Build the Rust enrollment backend (sim mode, /fixture enabled).
  execSync("cargo build -p enrollment-tee --features sim-fixture --bin tee-server", {
    cwd: REPO_ROOT,
    stdio: "inherit",
  });
  if (opts.separateVault) {
    execSync("cargo build -p voprf-vault --features http-server --bin voprf-vault", {
      cwd: REPO_ROOT,
      stdio: "inherit",
    });
  }
  // forge artifact must exist for the demo/server to deploy NullifierRegistry.
  execSync(`${join(FOUNDRY_BIN, "forge")} build --root ${join(REPO_ROOT, "contracts")}`, {
    stdio: "pipe",
  });

  const children: ChildProcess[] = [];
  const rpcUrl = `http://127.0.0.1:${anvilPort}`;
  const teeUrl = `http://127.0.0.1:${teePort}`;
  let vaultUrl: string | undefined;

  // O first: the tee needs it for Gate b. The tee-server honors VAULT_URL;
  // without it, it spawns its own in-process vault.
  const teeEnv: NodeJS.ProcessEnv = { ...process.env, TEE_ADDR: `127.0.0.1:${teePort}` };
  if (opts.separateVault) {
    vaultUrl = `http://127.0.0.1:${vaultPort}`;
    const vault = spawn(join(REPO_ROOT, "target", "debug", "voprf-vault"), [], {
      env: { ...process.env, VAULT_ADDR: `127.0.0.1:${vaultPort}` },
      stdio: "ignore",
    });
    children.push(vault);
    await waitFor(async () => {
      const res = await fetch(`${vaultUrl}/pubkey`);
      if (!res.ok) throw new Error(String(res.status));
    }, "voprf-vault");
    teeEnv.VAULT_URL = vaultUrl;
  }

  children.push(
    spawn(join(REPO_ROOT, "target", "debug", "tee-server"), [], { env: teeEnv, stdio: "ignore" }),
  );
  children.push(
    spawn(join(FOUNDRY_BIN, "anvil"), ["--port", String(anvilPort), "--silent"], {
      stdio: "ignore",
    }),
  );

  const provider = new JsonRpcProvider(rpcUrl, undefined, { pollingInterval: 50 });
  await waitFor(async () => {
    await provider.getBlockNumber();
  }, "anvil");
  await waitFor(async () => {
    const res = await fetch(`${teeUrl}/fixture`);
    if (!res.ok) throw new Error(String(res.status));
  }, "tee-server");
  provider.destroy();

  return {
    rpcUrl,
    teeUrl,
    vaultUrl,
    stop: () => {
      for (const c of children) c.kill();
    },
  };
}
