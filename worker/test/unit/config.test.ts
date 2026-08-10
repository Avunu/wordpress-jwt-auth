import { describe, it, expect } from "vitest";
import { loadConfig, ConfigError } from "../../src/config";
import type { AuthWorkerEnv } from "../../src/env";

function base(): Record<string, string> {
	return {
		ISSUER: "https://auth.example.com/",
		CLIENT_ID: "wordpress",
		ALLOWED_REDIRECT_URIS: '["https://example.com/?jwt_auth_callback=1"]',
		FROM_EMAIL: "login@example.com",
		TURNSTILE_SITE_KEY: "site",
		TURNSTILE_SECRET_KEY: "secret",
		SIGNING_KEY: "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n",
	};
}

/** A distinct env each time: loadConfig memoises the registry on the raw tenant source. */
function load(overrides: Record<string, string> = {}): ReturnType<typeof loadConfig> {
	return loadConfig({ ...base(), ...overrides } as unknown as AuthWorkerEnv);
}

function tenantJson(...tenants: Record<string, unknown>[]): string {
	return JSON.stringify(tenants);
}

describe("loadConfig — provider", () => {
	it("parses a valid bundle and strips the issuer trailing slash", () => {
		const { provider } = load();
		expect(provider.issuer).toBe("https://auth.example.com");
		expect(provider.issuerHost).toBe("auth.example.com");
		expect(provider.fromName).toBe("Sign in"); // Default applied
	});

	it("applies the default session windows and honours overrides", () => {
		expect(load().provider.sessionIdleMs).toBe(14 * 86_400_000);
		expect(load().provider.sessionAbsoluteMs).toBe(90 * 86_400_000);
		const custom = load({ SESSION_IDLE_DAYS: "3", SESSION_ABSOLUTE_DAYS: "30" });
		expect(custom.provider.sessionIdleMs).toBe(3 * 86_400_000);
		expect(custom.provider.sessionAbsoluteMs).toBe(30 * 86_400_000);
	});

	it(String.raw`normalises a \n-escaped PEM to real newlines`, () => {
		const { provider } = load({
			SIGNING_KEY: "-----BEGIN PRIVATE KEY-----\\nMIIabc\\n-----END PRIVATE KEY-----",
		});
		expect(provider.signingKeyPem).toContain("\n");
		expect(provider.signingKeyPem).not.toContain(String.raw`\n`);
	});

	it("throws ConfigError on a missing field", () => {
		const { ISSUER, ...rest } = base();
		void ISSUER;
		expect(() => loadConfig(rest as unknown as AuthWorkerEnv)).toThrow(ConfigError);
	});

	it("throws ConfigError when SIGNING_KEY is not a private key", () => {
		expect(() => load({ SIGNING_KEY: "just-a-string" })).toThrow(ConfigError);
	});
});

describe("loadConfig — legacy single-tenant vars", () => {
	it("synthesises one tenant from CLIENT_ID + ALLOWED_REDIRECT_URIS", () => {
		const tenant = load().tenants.get("wordpress");
		expect(tenant).not.toBeNull();
		expect(tenant?.redirectUris).toEqual(["https://example.com/?jwt_auth_callback=1"]);
		// Pre-fleet deployments have always shown the issuer host on their sign-in pages.
		expect(tenant?.displayName).toBe("auth.example.com");
		expect(tenant?.sso).toBe(true);
	});

	it("accepts a comma-separated redirect list", () => {
		const config = load({ ALLOWED_REDIRECT_URIS: "https://a.com/?x=1, https://b.com/?y=2" });
		expect(config.tenants.get("wordpress")?.redirectUris).toEqual([
			"https://a.com/?x=1",
			"https://b.com/?y=2",
		]);
	});

	it("throws ConfigError on an invalid redirect uri", () => {
		expect(() => load({ ALLOWED_REDIRECT_URIS: '["not-a-url"]' })).toThrow(ConfigError);
	});
});

describe("loadConfig — fleet registry", () => {
	const alpha = {
		clientId: "alpha",
		displayName: "Alpha",
		redirectUris: ["https://alpha.test/?jwt_auth_callback=1"],
	};
	const beta = {
		clientId: "beta",
		displayName: "Beta",
		redirectUris: ["https://beta.test/?jwt_auth_callback=1"],
	};

	it("prefers static tenants over env, and env TENANTS over the legacy vars", () => {
		const fromStatic = loadConfig(base() as unknown as AuthWorkerEnv, [alpha]);
		expect(fromStatic.tenants.get("alpha")?.displayName).toBe("Alpha");
		expect(fromStatic.tenants.get("wordpress")).toBeNull();

		const fromEnv = load({ TENANTS: tenantJson(beta) });
		expect(fromEnv.tenants.get("beta")?.displayName).toBe("Beta");
		expect(fromEnv.tenants.get("wordpress")).toBeNull();
	});

	it("rejects a duplicate clientId", () => {
		expect(() => load({ TENANTS: tenantJson(alpha, { ...beta, clientId: "alpha" }) })).toThrow(
			ConfigError,
		);
	});

	it("rejects a redirect URI claimed by two tenants", () => {
		expect(() =>
			load({ TENANTS: tenantJson(alpha, { ...beta, redirectUris: alpha.redirectUris }) }),
		).toThrow(ConfigError);
	});

	it("rejects malformed or empty tenant lists", () => {
		expect(() => load({ TENANTS: "not json" })).toThrow(ConfigError);
		expect(() => load({ TENANTS: "[]" })).toThrow(ConfigError);
		expect(() => load({ TENANTS: tenantJson({ clientId: "x" }) })).toThrow(ConfigError);
		expect(() => load({ TENANTS: tenantJson({ ...alpha, redirectUris: ["nope"] }) })).toThrow(
			ConfigError,
		);
	});

	it("resolves post-logout targets by origin, across every redirect URI a tenant owns", () => {
		const multi = {
			...alpha,
			redirectUris: [
				"https://alpha.test/?jwt_auth_callback=1",
				"https://recovery.alpha.test/?jwt_auth_callback=1",
			],
		};
		const { tenants } = load({ TENANTS: tenantJson(multi, beta) });

		expect(tenants.findPostLogoutTarget("https://alpha.test/")?.clientId).toBe("alpha");
		expect(tenants.findPostLogoutTarget("https://recovery.alpha.test/goodbye")?.clientId).toBe(
			"alpha",
		);
		expect(tenants.findPostLogoutTarget("https://beta.test/")?.clientId).toBe("beta");
		expect(tenants.findPostLogoutTarget("https://evil.test/")).toBeNull();
		expect(tenants.findPostLogoutTarget("not-a-url")).toBeNull();
	});

	it("honours explicit extra post-logout origins", () => {
		const { tenants } = load({
			TENANTS: tenantJson({ ...alpha, postLogoutRedirectUris: ["https://www.alpha.test/bye"] }),
		});
		expect(tenants.findPostLogoutTarget("https://www.alpha.test/")?.clientId).toBe("alpha");
	});
});
