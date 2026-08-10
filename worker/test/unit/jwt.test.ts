import { describe, it, expect } from "vitest";
import { generateKeyPair, exportPKCS8, jwtVerify, createLocalJWKSet, decodeJwt } from "jose";
import { signIdToken, publicJwks } from "../../src/lib/jwt";
import type { ProviderConfig } from "../../src/config";
import type { Identity } from "../../src/schemas";
import type { Tenant } from "../../src/tenant";

async function makeProvider(): Promise<ProviderConfig> {
	const { privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
	const signingKeyPem = await exportPKCS8(privateKey);
	return {
		issuer: "https://auth.avunu.io",
		issuerHost: "auth.avunu.io",
		fromEmail: "login@avunu.io",
		fromName: "Sign in",
		turnstileSiteKey: "site",
		turnstileSecretKey: "secret",
		signingKeyPem,
		sessionIdleMs: 1000,
		sessionAbsoluteMs: 2000,
	};
}

function tenant(clientId: string): Tenant {
	return {
		clientId,
		displayName: clientId,
		redirectUris: [`https://${clientId}.test/?jwt_auth_callback=1`],
		sso: true,
	};
}

describe("id_token signing + derived JWKS", () => {
	it("mints an RS256 token verifiable against the derived public JWKS", async () => {
		const provider = await makeProvider();
		const identity: Identity = { email: "user@example.com", sub: "pin:abc123" };

		const token = await signIdToken(provider, tenant("alpha"), identity, 300);
		const jwks = await publicJwks(provider);

		const { payload, protectedHeader } = await jwtVerify(token, createLocalJWKSet(jwks), {
			issuer: "https://auth.avunu.io",
			audience: "alpha",
		});

		expect(protectedHeader.alg).toBe("RS256");
		expect(protectedHeader.kid).toBeTruthy();
		expect(payload.sub).toBe("pin:abc123");
		expect(payload["email"]).toBe("user@example.com");
		// The token's kid matches the single published JWKS key.
		expect(jwks.keys[0]?.kid).toBe(protectedHeader.kid);
		// The published JWK never leaks private material.
		expect(jwks.keys[0]).not.toHaveProperty("d");
	});

	it("audiences each token to its own tenant, so one site's token is invalid at another", async () => {
		const provider = await makeProvider();
		const identity: Identity = { email: "user@example.com", sub: "pin:abc123" };
		const jwks = createLocalJWKSet(await publicJwks(provider));

		const alphaToken = await signIdToken(provider, tenant("alpha"), identity);
		expect(decodeJwt(alphaToken).aud).toBe("alpha");

		// Same issuer and same key — the audience is the only thing keeping the fleet apart, which
		// is exactly the check the WordPress plugin performs on arrival.
		await expect(
			jwtVerify(alphaToken, jwks, { issuer: provider.issuer, audience: "beta" }),
		).rejects.toThrow();
	});

	it("does not include name claims when the identity has none", async () => {
		const provider = await makeProvider();
		const token = await signIdToken(provider, tenant("alpha"), {
			email: "u@example.com",
			sub: "pin:x",
		});
		const { payload } = await jwtVerify(token, createLocalJWKSet(await publicJwks(provider)));
		expect(payload["name"]).toBeUndefined();
		expect(payload["given_name"]).toBeUndefined();
	});
});
