import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { generateKeyPair, exportPKCS8 } from "jose";
import { ISSUER, TENANTS } from "./test/integration/fleet";

// Integration tests run inside the real Workers runtime (workerd) so we can exercise the Durable
// Objects and the whole HTTP surface end-to-end: atomic attempt capping, single-use code minting,
// the code → identity/PKCE hand-off /token relies on, SSO sessions, and — most importantly — that
// one tenant can never reach another's redirect URI, code, or audience.
//
// The signing key is generated per run rather than committed: a fixture private key in git is a
// secret-scanner false positive at best and a habit worth not forming at worst.
//
// Vitest-pool-workers v0.18+ (for vitest 4) exposes its runtime as a Vite plugin,
// `cloudflareTest(workersConfig)`, rather than the older `poolOptions.workers` config.
export default defineConfig(async () => {
	const { privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });

	return {
		plugins: [
			cloudflareTest({
				wrangler: { configPath: "./wrangler.jsonc" },
				miniflare: {
					bindings: {
						ISSUER,
						TENANTS: JSON.stringify(TENANTS),
						FROM_EMAIL: "login@auth.test",
						FROM_NAME: "Test Sign-in",
						TURNSTILE_SITE_KEY: "1x00000000000000000000AA",
						TURNSTILE_SECRET_KEY: "1x0000000000000000000000000000000AA",
						SIGNING_KEY: await exportPKCS8(privateKey),
					},
					// The worker makes exactly one kind of outbound request — Turnstile siteverify — and
					// verifyTurnstile fails closed on any transport error, so without this the sandbox's
					// inability to reach Cloudflare would make every request_code test a 403 about
					// verification rather than a test of what it means to test. Answering "success" here
					// puts the human check out of the way so the code *after* it can be exercised.
					// Anything else outbound is refused rather than allowed through: a test that starts
					// depending on the network should fail loudly.
					outboundService(request: Request): Response {
						const url = new URL(request.url);
						if (url.hostname === "challenges.cloudflare.com") {
							return Response.json({ success: true });
						}
						return new Response(`unexpected outbound request to ${url.href}`, { status: 502 });
					},
				},
			}),
		],
		test: {
			include: ["test/integration/**/*.test.ts"],
		},
	};
});
