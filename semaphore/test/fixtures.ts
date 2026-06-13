import { PHI_LEN, SK_IDR_LEN } from "../src/identity.js";

/** Deterministic synthetic bytes. Real (Φ, sk_IdR) provenance — T releasing
 *  sk_IdR to C over the attested channel — is the SDK prompt's seam
 *  (docs/DECISIONS.md); the binding only sees bytes either way. */
export function fixtureBytes(len: number, tag: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = (i * 31 + tag * 17 + 7) & 0xff;
  return out;
}

export const userA = {
  phi: fixtureBytes(PHI_LEN, 1),
  skIdr: fixtureBytes(SK_IDR_LEN, 2),
};

export const userB = {
  phi: fixtureBytes(PHI_LEN, 3),
  skIdr: fixtureBytes(SK_IDR_LEN, 4),
};
