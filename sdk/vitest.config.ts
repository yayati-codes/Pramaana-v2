import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The e2e suite builds + spawns tee-server (cargo), boots anvil, and
    // generates Groth16 proofs (artifact download on first run).
    testTimeout: 120_000,
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
