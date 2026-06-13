import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Groth16 proof generation downloads snark artifacts on first run and
    // proving itself takes seconds; the on-chain suite also boots anvil.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Proof suites share the on-disk snark-artifact cache and one of them
    // boots anvil — keep files sequential.
    fileParallelism: false,
  },
});
