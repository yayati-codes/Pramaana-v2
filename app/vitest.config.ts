import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The demo e2e spawns cargo-built tee-server + anvil and generates
    // Groth16 proofs (artifact download on first run).
    testTimeout: 120_000,
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
