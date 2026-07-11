import { describe, it, expect } from "vitest";
import { generateKeyPair, exportPKCS8, jwtVerify, createLocalJWKSet } from "jose";
import { signIdToken, publicJwks } from "../../src/lib/jwt";
import type { AppConfig } from "../../src/config";
import type { Identity } from "../../src/schemas";

async function makeConfig(): Promise<AppConfig> {
  const { privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
  const signingKeyPem = await exportPKCS8(privateKey);
  return {
    issuer: "https://auth.example.com",
    issuerHost: "auth.example.com",
    clientId: "wordpress",
    allowedRedirectUris: ["https://example.com/?jwt_auth_callback=1"],
    fromEmail: "login@example.com",
    fromName: "Sign in",
    turnstileSiteKey: "site",
    turnstileSecretKey: "secret",
    signingKeyPem,
  };
}

describe("id_token signing + derived JWKS", () => {
  it("mints an RS256 token verifiable against the derived public JWKS", async () => {
    const config = await makeConfig();
    const identity: Identity = { email: "user@example.com", sub: "pin:abc123" };

    const token = await signIdToken(config, identity, 300);
    const jwks = await publicJwks(config);

    const { payload, protectedHeader } = await jwtVerify(token, createLocalJWKSet(jwks), {
      issuer: "https://auth.example.com",
      audience: "wordpress",
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

  it("does not include name claims when the identity has none", async () => {
    const config = await makeConfig();
    const token = await signIdToken(config, { email: "u@example.com", sub: "pin:x" });
    const { payload } = await jwtVerify(token, createLocalJWKSet(await publicJwks(config)));
    expect(payload["name"]).toBeUndefined();
    expect(payload["given_name"]).toBeUndefined();
  });
});
