/**
 * Sybil-resistant airdrop demo (ARCHITECTURE.md §3/§5): one human → one
 * claim per service, with cross-service pseudonyms that cannot be correlated.
 *
 * Run: `pnpm --filter @pramaana/app demo` (orchestrates anvil + tee-server),
 * then open the printed URL. Point at existing backends with TEE_URL/RPC_URL.
 */

import { createDemoServer } from "./server.js";
import { orchestrate, type Backends } from "./orchestrate.js";

async function main(): Promise<void> {
  const port = Number(process.env.PORT ?? 8080);

  let backends: Backends | null = null;
  let teeUrl = process.env.TEE_URL;
  let rpcUrl = process.env.RPC_URL;

  if (!teeUrl || !rpcUrl) {
    console.log("starting sim backends (anvil + tee-server)…");
    backends = await orchestrate();
    teeUrl = backends.teeUrl;
    rpcUrl = backends.rpcUrl;
  }

  const server = await createDemoServer({ teeUrl, rpcUrl });
  server.listen(port, () => {
    console.log(`\n  Pramaana demo → http://127.0.0.1:${port}\n`);
  });

  const shutdown = () => {
    server.close();
    backends?.stop();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
