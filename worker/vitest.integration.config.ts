import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

// Integration tests run inside the real Workers runtime (workerd) so we can exercise the
// LoginFlow Durable Object end-to-end: atomic attempt capping, single-use code minting, and
// the code → identity/PKCE-challenge hand-off that /token relies on.
//
// vitest-pool-workers v0.18 (for vitest 4) exposes its runtime as a Vite plugin,
// `cloudflareTest(workersConfig)`, rather than the older `poolOptions.workers` config.
export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
  test: {
    include: ["test/integration/**/*.test.ts"],
  },
});
