/**
 * DoD: same user, two serviceIds → two nullifiers with no shared derivable
 * value; correlation requires the user's secret. Plus proof round-trip and
 * tamper rejection. First run downloads the Groth16 artifacts (network).
 */

import { Group } from "@semaphore-protocol/core";
import { beforeAll, describe, expect, it } from "vitest";
import { deriveIdentity } from "../src/identity.js";
import { proveService, scopeOf, verifyService, type ServiceProof } from "../src/proof.js";
import { userA, userB } from "./fixtures.js";

const idA = deriveIdentity(userA.phi, userA.skIdr);
const idB = deriveIdentity(userB.phi, userB.skIdr);
const group = new Group([idA.commitment, idB.commitment]);

let aServiceA: ServiceProof;
let aServiceB: ServiceProof;
let bServiceA: ServiceProof;

beforeAll(async () => {
  [aServiceA, aServiceB, bServiceA] = await Promise.all([
    proveService(idA, group, "service-A"),
    proveService(idA, group, "service-B"),
    proveService(idB, group, "service-A"),
  ]);
});

describe("membership proofs (§3)", () => {
  it("round-trip: generated proofs verify", async () => {
    expect(await verifyService(aServiceA)).toBe(true);
    expect(await verifyService(aServiceB)).toBe(true);
    expect(await verifyService(bServiceA)).toBe(true);
  });

  it("same user, same service → the SAME nullifier (double-use is detectable)", async () => {
    const again = await proveService(idA, group, "service-A");
    expect(again.nullifier).toBe(aServiceA.nullifier);
  });

  it("tampered proofs are rejected", async () => {
    const wrongNullifier: ServiceProof = {
      ...aServiceA,
      nullifier: aServiceA.nullifier ^ 1n,
      proof: { ...aServiceA.proof, nullifier: (BigInt(aServiceA.proof.nullifier) ^ 1n).toString() },
    };
    expect(await verifyService(wrongNullifier)).toBe(false);

    const wrongPoints: ServiceProof = {
      ...aServiceA,
      proof: { ...aServiceA.proof, points: [...aServiceB.proof.points] },
    };
    expect(await verifyService(wrongPoints)).toBe(false);

    // Carried values must match the proof they came with.
    expect(await verifyService({ ...aServiceA, scope: scopeOf("service-B") })).toBe(false);
  });
});

describe("unlinkability across services (§3 DoD)", () => {
  it("two services → two different nullifiers; two users don't collide", () => {
    expect(aServiceA.nullifier).not.toBe(aServiceB.nullifier);
    expect(aServiceA.nullifier).not.toBe(bServiceA.nullifier);
  });

  it("the proofs' public values share no user-derivable value across services", () => {
    // Everything a verifier (or a colluding pair of services) sees:
    const publicValues = (p: ServiceProof) => ({
      root: BigInt(p.proof.merkleTreeRoot),
      depth: BigInt(p.proof.merkleTreeDepth),
      message: BigInt(p.proof.message),
      scope: p.scope,
      nullifier: p.nullifier,
    });
    const pa = publicValues(aServiceA);
    const pb = publicValues(aServiceB);

    // The user-specific values are pairwise distinct across the two proofs…
    expect(pa.nullifier).not.toBe(pb.nullifier);
    expect(pa.scope).not.toBe(pb.scope);
    const cross = [pa.nullifier, pa.scope].filter((v) => v === pb.nullifier || v === pb.scope);
    expect(cross).toHaveLength(0);

    // …and neither leaks the identity commitment.
    for (const v of [pa.nullifier, pb.nullifier]) {
      expect(v).not.toBe(idA.commitment);
    }

    // The ONLY shared values are group-wide, not user-specific: a DIFFERENT
    // user's proof carries the identical root/depth/message, so they cannot
    // single out the user. nullifier_s = H(scope, secret) — linking the two
    // nullifiers requires the user's secret.
    const pOther = publicValues(bServiceA);
    expect(pa.root).toBe(pb.root);
    expect(pa.root).toBe(pOther.root);
    expect(pa.depth).toBe(pOther.depth);
    expect(pa.message).toBe(pOther.message);
  });
});
