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

describe("loadConfig", () => {
  it("parses a valid bundle and strips the issuer trailing slash", () => {
    const c = loadConfig(base() as unknown as AuthWorkerEnv);
    expect(c.issuer).toBe("https://auth.example.com");
    expect(c.issuerHost).toBe("auth.example.com");
    expect(c.allowedRedirectUris).toEqual(["https://example.com/?jwt_auth_callback=1"]);
    expect(c.fromName).toBe("Sign in"); // default applied
  });

  it("accepts a comma-separated redirect list", () => {
    const env = { ...base(), ALLOWED_REDIRECT_URIS: "https://a.com/?x=1, https://b.com/?y=2" };
    const c = loadConfig(env as unknown as AuthWorkerEnv);
    expect(c.allowedRedirectUris).toEqual(["https://a.com/?x=1", "https://b.com/?y=2"]);
  });

  it("normalises a \\n-escaped PEM to real newlines", () => {
    const env = { ...base(), SIGNING_KEY: "-----BEGIN PRIVATE KEY-----\\nMIIabc\\n-----END PRIVATE KEY-----" };
    const c = loadConfig(env as unknown as AuthWorkerEnv);
    expect(c.signingKeyPem).toContain("\n");
    expect(c.signingKeyPem).not.toContain("\\n");
  });

  it("throws ConfigError on a missing field", () => {
    const { ISSUER, ...rest } = base();
    void ISSUER;
    expect(() => loadConfig(rest as unknown as AuthWorkerEnv)).toThrow(ConfigError);
  });

  it("throws ConfigError on an invalid redirect uri", () => {
    const env = { ...base(), ALLOWED_REDIRECT_URIS: '["not-a-url"]' };
    expect(() => loadConfig(env as unknown as AuthWorkerEnv)).toThrow(ConfigError);
  });

  it("throws ConfigError when SIGNING_KEY is not a private key", () => {
    const env = { ...base(), SIGNING_KEY: "just-a-string" };
    expect(() => loadConfig(env as unknown as AuthWorkerEnv)).toThrow(ConfigError);
  });
});
