import { defineConfig } from "vitest/config";

// Unit tests exercise the pure crypto/PKCE/OTP/JWT/config logic. Node 20+ provides the same
// WebCrypto SubtleCrypto primitives (RSASSA-PKCS1-v1_5, HMAC, SHA-256) as the Workers
// runtime, so these run in plain Node. Durable Object / handler integration tests would use
// @cloudflare/vitest-pool-workers instead.
export default defineConfig({
  test: {
    include: ["test/unit/**/*.test.ts"],
    environment: "node",
  },
});
