/**
 * DoD click-through, driven over the demo's HTTP API (the same calls the
 * browser makes): enroll → claim Alpha (claimed) → claim Alpha again
 * (blocked) → claim Beta (claimed) → Alpha vs Beta nullifiers are
 * uncorrelatable. Spawns anvil + tee-server + the app server.
 */

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDemoServer } from "../src/server.js";
import { orchestrate, type Backends } from "../src/orchestrate.js";

let backends: Backends;
let server: Server;
let base: string;

async function api(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ?? res.statusText);
  return data;
}

beforeAll(async () => {
  backends = await orchestrate({ anvilPort: 8551, teePort: 9971 });
  server = await createDemoServer({ teeUrl: backends.teeUrl, rpcUrl: backends.rpcUrl });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => {
  server?.close();
  backends?.stop();
});

describe("Sybil-resistant airdrop demo", () => {
  it("serves the UI", async () => {
    const res = await fetch(`${base}/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toContain("One human");
  });

  it("DoD: enroll → claim → second claim blocked → two services unlinkable", async () => {
    const enroll = await api("POST", "/api/enroll");
    expect(enroll.phi).toMatch(/^[0-9a-f]{128}$/); // Φ = SHA3-512
    expect(enroll.alreadyEnrolled).toBe(false);

    // Airdrop Alpha: first claim succeeds.
    const alpha1 = await api("POST", "/api/claim", { service: "airdrop-alpha" });
    expect(alpha1.status).toBe("claimed");

    // Same human, same airdrop, again → Sybil block (nullifier already spent).
    const alpha2 = await api("POST", "/api/claim", { service: "airdrop-alpha" });
    expect(alpha2.status).toBe("blocked");
    expect(alpha2.nullifier).toBe(alpha1.nullifier); // same deterministic nullifier

    // Airdrop Beta: independent service → claim succeeds for the same human.
    const beta1 = await api("POST", "/api/claim", { service: "airdrop-beta" });
    expect(beta1.status).toBe("claimed");

    // Unlinkability: the two services see different nullifiers and scopes,
    // sharing no value — they cannot correlate the same human.
    expect(beta1.nullifier).not.toBe(alpha1.nullifier);
    expect(beta1.scope).not.toBe(alpha1.scope);
    const seenByAlpha = [alpha1.nullifier, alpha1.scope];
    const seenByBeta = [beta1.nullifier, beta1.scope];
    expect(seenByAlpha.filter((v) => seenByBeta.includes(v))).toHaveLength(0);
  });

  it("reset clears the session", async () => {
    await api("POST", "/api/reset");
    const state = await api("GET", "/api/state");
    expect(state.enrollment).toBeNull();
    expect(Object.keys(state.claims)).toHaveLength(0);
  });
});
