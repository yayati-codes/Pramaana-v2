/**
 * Demo server: one server-side @pramaana/sdk session behind a tiny JSON API,
 * plus the static UI. The browser is pure presentation — running the SDK in
 * Node keeps the anvil deployer key server-side, avoids CORS to the Rust
 * tee-server, and skips an in-browser Groth16 artifact download.
 */

import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Pramaana, type ServiceProof } from "@pramaana/sdk";
import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";

/** The demo's two independent "services" — distinct external nullifiers. */
export const SERVICES = ["airdrop-alpha", "airdrop-beta"] as const;
export type ServiceId = (typeof SERVICES)[number];

// app/dist/server.js → repo root is three levels up (app/src too).
const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const PUBLIC_DIR = fileURLToPath(new URL("../public", import.meta.url));

// anvil's first dev account — SIM-ONLY demo deployer/signer.
const ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

export interface DemoServerConfig {
  teeUrl: string;
  rpcUrl: string;
  deployerKey?: string;
}

interface ClaimRecord {
  status: "claimed" | "blocked";
  nullifier: string;
  scope: string;
}

function nullifierHex(proof: ServiceProof): string {
  return `0x${proof.nullifier.toString(16).padStart(64, "0")}`;
}

/**
 * Deploys a fresh NullifierRegistry to the chain, then returns an http.Server
 * exposing the demo API + UI. One server = one demo "human".
 */
export async function createDemoServer(config: DemoServerConfig): Promise<Server> {
  const wallet = new Wallet(
    config.deployerKey ?? ANVIL_KEY0,
    new JsonRpcProvider(config.rpcUrl, undefined, {
      pollingInterval: 50,
      // The block/unblock claim flow sends near-identical calls back to back;
      // ethers' default result cache would mask the on-chain revert.
      cacheTimeout: -1,
    }),
  );
  const artifact = JSON.parse(
    readFileSync(
      join(REPO_ROOT, "contracts", "out", "NullifierRegistry.sol", "NullifierRegistry.json"),
      "utf8",
    ),
  );
  const registry = await new ContractFactory(
    artifact.abi,
    artifact.bytecode.object,
    wallet,
  ).deploy();
  await registry.waitForDeployment();
  const nullifierRegistryAddress = await registry.getAddress();

  // Mutable demo session (reset re-enrolls a "fresh human").
  let pramaana = newSession();
  let enrollment: { phi: string; alreadyEnrolled: boolean } | null = null;
  const claims = new Map<ServiceId, ClaimRecord>();

  function newSession(): Pramaana {
    return new Pramaana({ teeUrl: config.teeUrl, signer: wallet, nullifierRegistryAddress });
  }

  async function handleEnroll(): Promise<unknown> {
    const { qrNumeric, frames } = await pramaana.fixture();
    const handle = await pramaana.enroll(qrNumeric, { frames, capturedAtMs: Date.now() });
    enrollment = { phi: handle.phi, alreadyEnrolled: handle.alreadyEnrolled };
    return { phi: handle.phi, phiShort: shortHash(handle.phi), alreadyEnrolled: handle.alreadyEnrolled };
  }

  async function handleClaim(service: ServiceId): Promise<unknown> {
    if (!enrollment) throw new HttpError(400, "enroll first");
    const proof = await pramaana.prove(service);
    const record: ClaimRecord = {
      status: "claimed",
      nullifier: nullifierHex(proof),
      scope: `0x${proof.scope.toString(16)}`,
    };
    // Already spent (this human already claimed this airdrop) → Sybil block.
    if (!(await pramaana.verifyOnChain(proof))) {
      record.status = "blocked";
    } else {
      try {
        await pramaana.claim(proof);
      } catch (e) {
        if (String((e as Error).message).includes("NullifierAlreadySpent")) {
          record.status = "blocked";
        } else {
          throw e;
        }
      }
    }
    claims.set(service, record);
    return record;
  }

  function state(): unknown {
    return {
      services: SERVICES,
      enrollment: enrollment ? { ...enrollment, phiShort: shortHash(enrollment.phi) } : null,
      claims: Object.fromEntries(claims),
    };
  }

  return createServer((req, res) => {
    route(req, res, {
      "POST /api/enroll": handleEnroll,
      "POST /api/claim": async (body) => handleClaim(parseService(body)),
      "GET /api/state": async () => state(),
      "POST /api/reset": async () => {
        pramaana = newSession();
        enrollment = null;
        claims.clear();
        return { ok: true };
      },
    });
  });
}

// ---------------------------------------------------------------------------
// Tiny routing/static helpers (Node http only — no framework).
// ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

type Handler = (body: unknown) => Promise<unknown>;

function route(req: IncomingMessage, res: ServerResponse, handlers: Record<string, Handler>): void {
  const key = `${req.method} ${req.url?.split("?")[0]}`;
  const handler = handlers[key];

  if (!handler) {
    serveStatic(req, res);
    return;
  }

  const chunks: Buffer[] = [];
  req.on("data", (c) => chunks.push(c as Buffer));
  req.on("end", () => {
    void (async () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        const body = raw ? JSON.parse(raw) : {};
        const result = await handler(body);
        sendJson(res, 200, result);
      } catch (e) {
        const status = e instanceof HttpError ? e.status : 500;
        sendJson(res, status, { error: (e as Error).message });
      }
    })();
  });
}

function serveStatic(req: IncomingMessage, res: ServerResponse): void {
  const path = req.url?.split("?")[0] ?? "/";
  const file = path === "/" ? "index.html" : path.replace(/^\/+/, "");
  // Confine to PUBLIC_DIR (no traversal).
  if (file.includes("..")) {
    sendJson(res, 400, { error: "bad path" });
    return;
  }
  try {
    const body = readFileSync(join(PUBLIC_DIR, file));
    res.writeHead(200, { "content-type": contentType(file) });
    res.end(body);
  } catch {
    sendJson(res, 404, { error: "not found" });
  }
}

function parseService(body: unknown): ServiceId {
  const service = (body as { service?: string }).service;
  if (!SERVICES.includes(service as ServiceId)) {
    throw new HttpError(400, `unknown service ${String(service)}`);
  }
  return service as ServiceId;
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(payload));
}

function contentType(file: string): string {
  if (file.endsWith(".html")) return "text/html; charset=utf-8";
  if (file.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (file.endsWith(".css")) return "text/css; charset=utf-8";
  return "application/octet-stream";
}

function shortHash(hex: string): string {
  return `${hex.slice(0, 10)}…${hex.slice(-6)}`;
}
