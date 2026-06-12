/**
 * Sybil-resistant airdrop demo (ARCHITECTURE.md §5).
 * One human → one claim, no matter how many wallets they control.
 */
import { enroll, prove, verifyOnChain } from "@pramaana/sdk";

const AIRDROP_SERVICE_ID = "pramaana-airdrop-demo";

async function main(): Promise<void> {
  // One-time: prove real-world uniqueness inside the enrollment TEE (§2).
  const enrollment = await enroll();
  console.log("enrolled, Φ =", enrollment.phi);

  // Per-service: unlinkable pseudonym + Semaphore membership proof (§3).
  const claim = await prove(AIRDROP_SERVICE_ID);

  // The airdrop accepts each nullifier exactly once.
  const accepted = await verifyOnChain(claim);
  console.log("claim accepted:", accepted);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
