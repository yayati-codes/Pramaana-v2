import { describe, expect, it } from "vitest";
import { deriveIdentity, PHI_LEN, SK_IDR_LEN } from "../src/identity.js";
import { fixtureBytes, userA, userB } from "./fixtures.js";

describe("deriveIdentity", () => {
  it("is deterministic: same (phi, skIdr) → same commitment", () => {
    const a1 = deriveIdentity(userA.phi, userA.skIdr);
    const a2 = deriveIdentity(userA.phi, userA.skIdr);
    expect(a1.commitment).toBe(a2.commitment);
  });

  it("different skIdr → different identity (same public phi)", () => {
    // Φ is on-chain/public; the secret MUST hinge on sk_IdR.
    const a = deriveIdentity(userA.phi, userA.skIdr);
    const other = deriveIdentity(userA.phi, userB.skIdr);
    expect(a.commitment).not.toBe(other.commitment);
  });

  it("different phi → different identity", () => {
    const a = deriveIdentity(userA.phi, userA.skIdr);
    const b = deriveIdentity(userB.phi, userA.skIdr);
    expect(a.commitment).not.toBe(b.commitment);
  });

  it("rejects wrong-length inputs", () => {
    expect(() => deriveIdentity(fixtureBytes(PHI_LEN - 1, 1), userA.skIdr)).toThrow(/phi/);
    expect(() => deriveIdentity(userA.phi, fixtureBytes(0, 2))).toThrow(/skIdr/);
    expect(() => deriveIdentity(userA.phi, fixtureBytes(SK_IDR_LEN + 1, 2))).toThrow(/skIdr/);
  });
});
