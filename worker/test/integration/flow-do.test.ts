import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { hashSecret } from "../../src/lib/otp";
import type { LoginFlow } from "../../src/flow-do";
import type { FlowContext } from "../../src/schemas";

// PKCE S256 pair (RFC 7636 Appendix B) — the DO stores/returns the challenge; /token proves
// the verifier. Here we just assert the challenge round-trips out of consumeCode.
const CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT = "https://site.example/?jwt_auth_callback=1";

function context(): FlowContext {
  return {
    clientId: "wordpress",
    redirectUri: REDIRECT,
    wpState: "wp-state-123",
    scope: "openid email profile",
    codeChallenge: CODE_CHALLENGE,
    createdAt: Date.now(),
  };
}

function stubFor(flowId: string): DurableObjectStub<LoginFlow> {
  return env.LOGIN_FLOW.get(env.LOGIN_FLOW.idFromName(flowId));
}

describe("LoginFlow Durable Object", () => {
  it("caps wrong-PIN attempts at 5 and then locks", async () => {
    const flowId = "flow-attempts";
    const stub = stubFor(flowId);
    await stub.create(context());
    const pinHash = await hashSecret("123456", flowId);
    await stub.setChallenge("user@example.com", pinHash, await hashSecret("tok", flowId));

    const wrong = await hashSecret("000000", flowId);
    for (let i = 0; i < 5; i++) {
      const r = await stub.verifyPin(wrong);
      expect(r).toEqual({ ok: false, reason: "invalid" });
    }
    // Even the correct PIN is now refused — the flow is locked.
    const afterLock = await stub.verifyPin(pinHash);
    expect(afterLock).toEqual({ ok: false, reason: "locked" });
  });

  it("verifies the correct PIN, mints a flow-addressed single-use code, and consumes it once", async () => {
    const flowId = "flow-success";
    const stub = stubFor(flowId);
    await stub.create(context());
    const pinHash = await hashSecret("654321", flowId);
    await stub.setChallenge("User@Example.com".toLowerCase(), pinHash, await hashSecret("tok", flowId));

    const verified = await stub.verifyPin(pinHash);
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;
    expect(verified.code.startsWith(`${flowId}.`)).toBe(true);
    expect(verified.redirectUri).toBe(REDIRECT);
    expect(verified.state).toBe("wp-state-123");

    // /token's consume: returns identity + the PKCE challenge, and is strictly single-use.
    const first = await stub.consumeCode(verified.code, REDIRECT);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.codeChallenge).toBe(CODE_CHALLENGE);
    expect(first.identity.email).toBe("user@example.com");
    expect(first.identity.sub.startsWith("pin:")).toBe(true);

    const second = await stub.consumeCode(verified.code, REDIRECT);
    expect(second).toEqual({ ok: false, reason: "used" });
  });

  it("rejects consuming a code with a mismatched redirect_uri", async () => {
    const flowId = "flow-redirect";
    const stub = stubFor(flowId);
    await stub.create(context());
    const pinHash = await hashSecret("111111", flowId);
    await stub.setChallenge("user@example.com", pinHash, await hashSecret("tok", flowId));

    const verified = await stub.verifyPin(pinHash);
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;

    const wrongRedirect = await stub.consumeCode(verified.code, "https://evil.example/?jwt_auth_callback=1");
    expect(wrongRedirect).toEqual({ ok: false, reason: "redirect_mismatch" });
  });

  it("verifies a magic-link token exactly like a PIN", async () => {
    const flowId = "flow-magic";
    const stub = stubFor(flowId);
    await stub.create(context());
    const magicHash = await hashSecret("magic-secret-token", flowId);
    await stub.setChallenge("user@example.com", await hashSecret("999999", flowId), magicHash);

    const bad = await stub.verifyMagic(await hashSecret("wrong-token", flowId));
    expect(bad.ok).toBe(false);

    const good = await stub.verifyMagic(await hashSecret("magic-secret-token", flowId));
    expect(good.ok).toBe(true);
    if (!good.ok) return;
    expect(good.code.startsWith(`${flowId}.`)).toBe(true);
  });

  it("returns not_found for an unknown flow", async () => {
    const stub = stubFor("flow-never-created");
    expect(await stub.getContext()).toBeNull();
    const consumed = await stub.consumeCode("flow-never-created.deadbeef", REDIRECT);
    expect(consumed).toEqual({ ok: false, reason: "not_found" });
  });
});
