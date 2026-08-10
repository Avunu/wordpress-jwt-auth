import { env, exports } from "cloudflare:workers";
import { describe, it, expect } from "vitest";
import { createLocalJWKSet, jwtVerify, decodeJwt } from "jose";
import type { JSONWebKeySet } from "jose";
import type { LoginFlow } from "../../src/flow-do";
import type { UserSession } from "../../src/session-do";
import type { FlowContext } from "../../src/schemas";
import {
	ALPHA_REDIRECT,
	BETA_REDIRECT,
	CODE_CHALLENGE,
	CODE_VERIFIER,
	ISSUER,
	SOLO_REDIRECT,
} from "./fleet";

// End-to-end HTTP tests against the real router. The point of most of them is negative: prove that
// belonging to the fleet gets a site exactly its own tokens and nowhere else's.

const EMAIL = "user@example.com";

function authorizeUrl(params: Record<string, string>): string {
	const url = new URL(`${ISSUER}/authorize`);
	for (const [k, v] of Object.entries({
		response_type: "code",
		scope: "openid email profile",
		state: "wp-state-123",
		code_challenge: CODE_CHALLENGE,
		code_challenge_method: "S256",
		...params,
	})) {
		url.searchParams.set(k, v);
	}
	return url.toString();
}

/** GET without following the 302, so we can inspect where it wanted to send the browser. */
function get(url: string, cookie?: string): Promise<Response> {
	return exports.default.fetch(url, {
		redirect: "manual",
		...(cookie ? { headers: { Cookie: cookie } } : {}),
	});
}

function postForm(url: string, body: Record<string, string>, cookie?: string): Promise<Response> {
	return exports.default.fetch(url, {
		method: "POST",
		redirect: "manual",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			...(cookie ? { Cookie: cookie } : {}),
		},
		body: new URLSearchParams(body).toString(),
	});
}

function flowStub(flowId: string): DurableObjectStub<LoginFlow> {
	return env.LOGIN_FLOW.get(env.LOGIN_FLOW.idFromName(flowId));
}

function sessionStub(sessionId: string): DurableObjectStub<UserSession> {
	const namespace = env.SSO_SESSION;
	if (!namespace) {
		throw new Error("SSO_SESSION binding missing from the test environment");
	}
	return namespace.get(namespace.idFromName(sessionId));
}

function context(clientId: string, redirectUri: string): FlowContext {
	return {
		clientId,
		redirectUri,
		wpState: "wp-state-123",
		scope: "openid email profile",
		codeChallenge: CODE_CHALLENGE,
		createdAt: Date.now(),
	};
}

/** Mint a real authorization code for a tenant, the way a completed sign-in would. */
async function mintCodeFor(flowId: string, clientId: string, redirectUri: string): Promise<string> {
	const minted = await flowStub(flowId).createAndComplete(context(clientId, redirectUri), EMAIL);
	return minted.code;
}

/** Start an SSO session already linked to `clientId`, and return its Cookie header. */
async function startSessionCookie(sessionId: string, clientId: string): Promise<string> {
	await sessionStub(sessionId).start(EMAIL, clientId, 86_400_000, 86_400_000);
	return `__Host-sso=${sessionId}`;
}

async function jwks(): Promise<ReturnType<typeof createLocalJWKSet>> {
	const res = await exports.default.fetch(`${ISSUER}/.well-known/jwks.json`);
	return createLocalJWKSet((await res.json()) as JSONWebKeySet);
}

describe("discovery", () => {
	it("serves one document for the whole fleet", async () => {
		const res = await exports.default.fetch(`${ISSUER}/.well-known/openid-configuration`);
		const doc = (await res.json()) as Record<string, string>;
		expect(doc["issuer"]).toBe(ISSUER);
		expect(doc["authorization_endpoint"]).toBe(`${ISSUER}/authorize`);
		expect(doc["jwks_uri"]).toBe(`${ISSUER}/.well-known/jwks.json`);
	});
});

describe("GET /authorize — tenant resolution", () => {
	it("renders the tenant's own name and opens a flow", async () => {
		const res = await get(authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }));
		expect(res.status).toBe(200);
		const html = await res.text();
		expect(html).toContain("Alpha Site");
		expect(html).not.toContain("Beta Site");
		expect(res.headers.get("Set-Cookie")).toContain("__Host-wp_auth_flow=");
		// One host now fronts every brand, so the login pages carry their own hardening.
		expect(res.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
		expect(res.headers.get("Cache-Control")).toBe("no-store");
	});

	it("rejects an unknown client_id", async () => {
		const res = await get(authorizeUrl({ client_id: "nobody", redirect_uri: ALPHA_REDIRECT }));
		expect(res.status).toBe(400);
	});

	it("rejects one tenant's client_id paired with another tenant's redirect_uri", async () => {
		const res = await get(authorizeUrl({ client_id: "alpha", redirect_uri: BETA_REDIRECT }));
		expect(res.status).toBe(400);
		expect(await res.text()).toContain("not authorised");
	});

	it("rejects a redirect_uri no tenant has registered", async () => {
		const res = await get(
			authorizeUrl({ client_id: "alpha", redirect_uri: "https://evil.test/?jwt_auth_callback=1" }),
		);
		expect(res.status).toBe(400);
	});

	it("accepts any of a tenant's registered redirect URIs", async () => {
		const res = await get(
			authorizeUrl({
				client_id: "alpha",
				redirect_uri: "https://recovery.alpha.test/?jwt_auth_callback=1",
			}),
		);
		expect(res.status).toBe(200);
	});
});

describe("POST /token — code ownership", () => {
	function tokenBody(code: string, clientId: string, redirectUri: string): Record<string, string> {
		return {
			grant_type: "authorization_code",
			code,
			redirect_uri: redirectUri,
			code_verifier: CODE_VERIFIER,
			client_id: clientId,
		};
	}

	it("exchanges a code for an id_token audienced to that tenant", async () => {
		const code = await mintCodeFor("tok-ok", "alpha", ALPHA_REDIRECT);
		const res = await postForm(`${ISSUER}/token`, tokenBody(code, "alpha", ALPHA_REDIRECT));
		expect(res.status).toBe(200);

		const body = (await res.json()) as { id_token: string };
		const { payload } = await jwtVerify(body.id_token, await jwks(), {
			issuer: ISSUER,
			audience: "alpha",
		});
		expect(payload["email"]).toBe(EMAIL);
		expect(payload.sub).toMatch(/^pin:/);
	});

	it("refuses a code minted for another tenant", async () => {
		const code = await mintCodeFor("tok-cross", "alpha", ALPHA_REDIRECT);
		// Beta knows the code and asks for it under its own identity. It must not receive a token —
		// least of all one stamped `aud: beta`.
		const res = await postForm(`${ISSUER}/token`, tokenBody(code, "beta", ALPHA_REDIRECT));
		expect(res.status).toBe(400);
		expect((await res.json()) as { error: string }).toMatchObject({ error: "invalid_grant" });
	});

	it("refuses an unknown client", async () => {
		const code = await mintCodeFor("tok-unknown", "alpha", ALPHA_REDIRECT);
		const res = await postForm(`${ISSUER}/token`, tokenBody(code, "nobody", ALPHA_REDIRECT));
		expect(res.status).toBe(401);
		expect((await res.json()) as { error: string }).toMatchObject({ error: "invalid_client" });
	});

	it("refuses a mismatched PKCE verifier, and refuses to reuse a code", async () => {
		const code = await mintCodeFor("tok-pkce", "alpha", ALPHA_REDIRECT);
		const wrong = await postForm(`${ISSUER}/token`, {
			...tokenBody(code, "alpha", ALPHA_REDIRECT),
			code_verifier: "x".repeat(43),
		});
		expect(wrong.status).toBe(400);

		// The failed PKCE attempt still consumed the code; a correct verifier can't rescue it.
		const replay = await postForm(`${ISSUER}/token`, tokenBody(code, "alpha", ALPHA_REDIRECT));
		expect(replay.status).toBe(400);
	});
});

describe("cross-site SSO", () => {
	it("signs in silently at a site the session has already used", async () => {
		const cookie = await startSessionCookie("sso-silent", "alpha");
		const res = await get(
			authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }),
			cookie,
		);

		expect(res.status).toBe(302);
		const location = new URL(res.headers.get("Location") ?? "");
		expect(location.origin + location.pathname).toBe("https://alpha.test/");
		expect(location.searchParams.get("state")).toBe("wp-state-123");
		expect(location.searchParams.get("code")).toBeTruthy();
	});

	it("asks for confirmation at a site the session has never used", async () => {
		const cookie = await startSessionCookie("sso-new-site", "alpha");
		const res = await get(authorizeUrl({ client_id: "beta", redirect_uri: BETA_REDIRECT }), cookie);

		// Never silent: an unrelated brand does not get an account created behind the user's back.
		expect(res.status).toBe(200);
		const html = await res.text();
		expect(html).toContain("Beta Site");
		expect(html).toContain(EMAIL);
		expect(html).toContain("continue_sso");
	});

	it("completes the confirmation and is silent from then on", async () => {
		const cookie = await startSessionCookie("sso-confirm", "alpha");
		const first = await get(
			authorizeUrl({ client_id: "beta", redirect_uri: BETA_REDIRECT }),
			cookie,
		);
		const [flowCookie] = (first.headers.get("Set-Cookie") ?? "").split(";");
		expect(flowCookie).toContain("__Host-wp_auth_flow=");

		const confirmed = await postForm(
			`${ISSUER}/authorize`,
			{ action: "continue_sso" },
			`${cookie}; ${flowCookie}`,
		);
		expect(confirmed.status).toBe(302);
		expect(confirmed.headers.get("Location")).toContain("https://beta.test/");

		// Beta is now linked, so a fresh authorize needs no interaction at all.
		const again = await get(
			authorizeUrl({ client_id: "beta", redirect_uri: BETA_REDIRECT }),
			cookie,
		);
		expect(again.status).toBe(302);
	});

	it("mints a token audienced to the site being visited", async () => {
		const cookie = await startSessionCookie("sso-aud", "alpha");
		const res = await get(
			authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }),
			cookie,
		);
		const code = new URL(res.headers.get("Location") ?? "").searchParams.get("code") ?? "";
		const token = await postForm(`${ISSUER}/token`, {
			grant_type: "authorization_code",
			code,
			redirect_uri: ALPHA_REDIRECT,
			code_verifier: CODE_VERIFIER,
			client_id: "alpha",
		});
		const body = (await token.json()) as { id_token: string };
		expect(decodeJwt(body.id_token).aud).toBe("alpha");
	});

	it("honours prompt=login by demanding a fresh email even with a live session", async () => {
		const cookie = await startSessionCookie("sso-prompt", "alpha");
		const res = await get(
			authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT, prompt: "login" }),
			cookie,
		);
		expect(res.status).toBe(200);
		expect(await res.text()).toContain("Email me a code");
	});

	it("never signs in silently at a tenant with sso disabled", async () => {
		const cookie = await startSessionCookie("sso-off", "solo");
		const res = await get(authorizeUrl({ client_id: "solo", redirect_uri: SOLO_REDIRECT }), cookie);
		expect(res.status).toBe(200);
		expect(await res.text()).toContain("Email me a code");
	});

	it("ignores a cookie pointing at a session that no longer exists", async () => {
		const res = await get(
			authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }),
			"__Host-sso=never-existed",
		);
		expect(res.status).toBe(200);
		expect(await res.text()).toContain("Email me a code");
	});
});

describe("GET /logout", () => {
	it("redirects to an allowed post-logout origin and ends the SSO session", async () => {
		const cookie = await startSessionCookie("logout-session", "alpha");
		const res = await get(
			`${ISSUER}/logout?post_logout_redirect_uri=${encodeURIComponent("https://alpha.test/")}`,
			cookie,
		);
		expect(res.status).toBe(302);
		expect(res.headers.get("Location")).toBe("https://alpha.test/");
		expect(res.headers.get("Set-Cookie")).toContain("__Host-sso=;");

		// The session is genuinely gone, so the next visit — even to the site it was created on —
		// asks for an email again. This is what makes switching accounts possible.
		const after = await get(
			authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }),
			cookie,
		);
		expect(after.status).toBe(200);
		expect(await after.text()).toContain("Email me a code");
	});

	it("refuses to redirect to an origin no tenant registered", async () => {
		const res = await get(
			`${ISSUER}/logout?post_logout_redirect_uri=${encodeURIComponent("https://evil.test/")}`,
		);
		expect(res.status).toBe(200);
		expect(res.headers.get("Location")).toBeNull();
	});

	it("still signs out when given no target at all", async () => {
		const cookie = await startSessionCookie("logout-bare", "alpha");
		const res = await get(`${ISSUER}/logout`, cookie);
		expect(res.status).toBe(200);
		expect(res.headers.get("Set-Cookie")).toContain("__Host-sso=;");
	});
});

describe("routing", () => {
	it("404s an unknown path and a wrong method", async () => {
		const unknownPath = await exports.default.fetch(`${ISSUER}/nope`);
		expect(unknownPath.status).toBe(404);
		const wrongMethod = await exports.default.fetch(`${ISSUER}/token`, { method: "GET" });
		expect(wrongMethod.status).toBe(404);
	});
});
