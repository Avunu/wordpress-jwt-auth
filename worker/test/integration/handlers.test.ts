import { env, exports } from "cloudflare:workers";
import { describe, it, expect } from "vitest";
import { createLocalJWKSet, jwtVerify, decodeJwt } from "jose";
import type { JSONWebKeySet } from "jose";
import type { LoginFlow } from "../../src/flow-do";
import type { UserSession } from "../../src/session-do";
import type { FlowContext } from "../../src/schemas";
import { hashSecret } from "../../src/lib/otp";
import { CLIENT_SOURCE_HASH } from "../../src/client";
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

/** The same post, but as the enhanced client makes it. */
function postPartial(
	url: string,
	body: Record<string, string>,
	cookie?: string,
): Promise<Response> {
	return exports.default.fetch(url, {
		method: "POST",
		redirect: "manual",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			"X-Partial": "1",
			...(cookie ? { Cookie: cookie } : {}),
		},
		body: new URLSearchParams(body).toString(),
	});
}

/** The flow id inside a `__Host-wp_auth_flow=…` cookie fragment, which forms must now echo. */
function flowIdFrom(cookieFragment: string | undefined): string {
	return (cookieFragment ?? "").split("=")[1] ?? "";
}

/** Drive a flow to the point where the next correct PIN completes it. */
async function armedFlow(flowId: string, pin: string, clientId = "alpha"): Promise<string> {
	const stub = flowStub(flowId);
	const redirectUri = clientId === "alpha" ? ALPHA_REDIRECT : BETA_REDIRECT;
	await stub.create(context(clientId, redirectUri));
	await stub.setChallenge(EMAIL, await hashSecret(pin, flowId), await hashSecret("tok", flowId));
	return `__Host-wp_auth_flow=${flowId}`;
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
		expect(res.headers.get("X-Frame-Options")).toBe("DENY");
	});

	it("keeps the sign-in pages out of shared caches without costing the back/forward cache", async () => {
		// no-store would evict the page from the bfcache, and the PIN step is precisely where people
		// leave to go and read their email. no-cache keeps shared caches out without that cost.
		const res = await get(authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }));

		expect(res.headers.get("Cache-Control")).toContain("no-cache");
		expect(res.headers.get("Cache-Control")).not.toContain("no-store");
	});

	it("does not restrict form-action, which would block the redirect that ends a sign-in", async () => {
		// Chrome applies form-action to the redirect *resulting* from a form POST, and a successful
		// PIN submission is answered with a 302 to the WordPress site — cross-origin by definition.
		const res = await get(authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }));

		expect(res.headers.get("Content-Security-Policy")).not.toContain("form-action");
	});

	it("re-issues the flow cookie on every step that keeps the flow open", async () => {
		// The browser must never be the component that decides a sign-in has expired: its copy of the
		// handle outlives the flow, and every interaction refreshes it. Otherwise a user who spends
		// the budget waiting for the email loses the cookie mid-flow and gets "session expired" with
		// no way to tell it apart from a genuinely dead flow.
		const first = await get(authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }));
		const setCookie = first.headers.get("Set-Cookie") ?? "";
		expect(setCookie).toContain("__Host-wp_auth_flow=");
		expect(setCookie).toContain("Max-Age=900");
		// __Host- requires Secure + Path=/ and forbids Domain, or the browser drops it silently.
		expect(setCookie).toContain("Secure");
		expect(setCookie).toContain("Path=/");
		expect(setCookie).not.toContain("Domain=");

		const [flowCookie] = setCookie.split(";");
		const stepped = await postForm(
			`${ISSUER}/authorize`,
			{ step: "change_email", flow: flowIdFrom(flowCookie) },
			flowCookie ?? "",
		);
		expect(stepped.status).toBe(200);
		expect(stepped.headers.get("Set-Cookie")).toContain("Max-Age=900");
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

describe("enhanced (fetch) submissions", () => {
	it("answers a completed sign-in with 200 + a redirect header, never a 302", async () => {
		// The whole point. fetch() follows a 302 transparently, so a redirecting response would hand
		// the client the WordPress page's HTML to swap into the card. The header instead lets the
		// client navigate itself — a script navigation, which form-action does not govern.
		const cookie = await armedFlow("partial-success", "424242");

		const res = await postPartial(
			`${ISSUER}/authorize`,
			{ step: "verify_code", pin: "424242", flow: "partial-success" },
			cookie,
		);

		expect(res.status).toBe(200);
		expect(res.headers.get("Location")).toBeNull();
		const to = new URL(res.headers.get("X-Auth-Redirect") ?? "");
		expect(to.origin + to.pathname).toBe("https://alpha.test/");
		expect(to.searchParams.get("code")).toBeTruthy();
		expect(to.searchParams.get("state")).toBe("wp-state-123");
		// The SSO session still starts — the enhanced path must not lose it.
		expect(res.headers.get("Set-Cookie")).toContain("__Host-sso=");
	});

	it("still answers a plain browser with a 302", async () => {
		// Same request, no X-Partial: the no-JS path is unchanged.
		const cookie = await armedFlow("plain-success", "515151");

		const res = await postForm(
			`${ISSUER}/authorize`,
			{ step: "verify_code", pin: "515151", flow: "plain-success" },
			cookie,
		);

		expect(res.status).toBe(302);
		expect(res.headers.get("X-Auth-Redirect")).toBeNull();
		expect(res.headers.get("Location")).toContain("https://alpha.test/");
	});

	it("returns a bare card, not a document, and keeps the status", async () => {
		const cookie = await armedFlow("partial-error", "616161");

		const res = await postPartial(
			`${ISSUER}/authorize`,
			{ step: "verify_code", pin: "000000", flow: "partial-error" },
			cookie,
		);

		expect(res.status).toBe(401);
		const html = await res.text();
		expect(html).not.toContain("<html");
		expect(html).not.toContain("<!doctype");
		expect(html.trimStart().startsWith('<div class="card" id="card"')).toBe(true);
		expect(html).toContain("That code is incorrect");
	});

	it("serves the same card inside a document for a plain browser", async () => {
		const cookie = await armedFlow("plain-error", "717171");

		const res = await postForm(
			`${ISSUER}/authorize`,
			{ step: "verify_code", pin: "000000", flow: "plain-error" },
			cookie,
		);

		expect(res.status).toBe(401);
		const html = await res.text();
		expect(html).toContain("<!doctype html>");
		expect(html).toContain('<div class="card" id="card"');
		expect(html).toContain("That code is incorrect");
	});

	it("carries the script under a hash so no inline-script allowance is needed", async () => {
		const res = await get(authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }));
		const csp = res.headers.get("Content-Security-Policy") ?? "";

		expect(csp).toContain(`script-src '${CLIENT_SOURCE_HASH}'`);
		expect(csp).not.toContain("unsafe-inline'; script");
		expect(csp).not.toContain("'unsafe-eval'");
		// The client posts back to us over fetch, which default-src 'none' would otherwise block.
		expect(csp).toContain("connect-src 'self'");
	});

	it("gives every form a real action and method so a blocked script cannot strand anyone", async () => {
		const res = await get(authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }));
		const html = await res.text();

		expect(html).toContain('<form data-enhance method="post" action="/authorize"');
		expect(html).not.toMatch(/<form(?![^>]*\baction=)/);
	});
});

describe("submitting a code twice", () => {
	it("keeps the flow handle on success, so a second submit can be explained", async () => {
		// The bug this replaces: the success redirect also cleared the flow cookie. A browser applies
		// Set-Cookie even from a response whose navigation it abandons, so the second press arrived
		// with no handle and got "this sign-in session has expired" — when in fact the sign-in had
		// just succeeded.
		const cookie = await startSessionCookie("reuse-cookie", "alpha");
		const res = await get(
			authorizeUrl({ client_id: "alpha", redirect_uri: ALPHA_REDIRECT }),
			cookie,
		);

		expect(res.status).toBe(302);
		const setCookie = res.headers.get("Set-Cookie") ?? "";
		expect(setCookie).not.toMatch(/__Host-wp_auth_flow=;/);
		expect(setCookie).not.toMatch(/__Host-wp_auth_flow=[^;]*Max-Age=0/);
	});

	it("tells a repeat submitter they are already signed in", async () => {
		// Drive a real flow to completion through the DO, then re-submit against the live handler.
		const flowId = "reuse-handler";
		const stub = flowStub(flowId);
		await stub.create(context("alpha", ALPHA_REDIRECT));
		const pinHash = await hashSecret("135790", flowId);
		await stub.setChallenge(EMAIL, pinHash, await hashSecret("tok", flowId));
		const completed = await stub.verifyPin(pinHash);
		expect(completed.ok).toBe(true);

		const res = await postForm(
			`${ISSUER}/authorize`,
			{ step: "verify_code", pin: "135790", flow: flowId },
			`__Host-wp_auth_flow=${flowId}`,
		);

		const html = await res.text();
		expect(html).toContain("already signed in");
		expect(html).toContain("Alpha Site");
		expect(html).not.toContain("session has expired");
		expect(html).not.toContain("incorrect");
	});
});

describe("security regressions", () => {
	it("refuses a cross-site POST to /magic", async () => {
		// Login CSRF. The endpoint takes no cookie by design, so SameSite protects nothing: an
		// attacker holding their OWN unspent magic token can auto-submit it from a page the victim
		// loads, minting a code into the victim's browser and — worse — an SSO cookie bound to the
		// attacker's identity, after which the whole fleet signs the victim in as the attacker.
		const flow = "magic-csrf";
		const stub = flowStub(flow);
		await stub.create(context("alpha", ALPHA_REDIRECT));
		await stub.setChallenge(EMAIL, await hashSecret("111111", flow), await hashSecret("tok", flow));

		const res = await exports.default.fetch(`${ISSUER}/magic`, {
			method: "POST",
			redirect: "manual",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				// What a cross-origin auto-submitting form actually sends.
				"Sec-Fetch-Site": "cross-site",
				Origin: "https://evil.test",
			},
			body: new URLSearchParams({ flow, token: "tok" }).toString(),
		});

		expect(res.status).toBe(410);
		expect(res.headers.get("Set-Cookie")).toBeNull(); // no SSO session planted
		expect(res.headers.get("Location")).toBeNull(); // no code handed out
		// And the token is still unspent, so the real human's click still works.
		const still = await stub.verifyMagic(await hashSecret("tok", flow));
		expect(still.ok).toBe(true);
	});

	it("still accepts the same-origin POST the confirm page makes", async () => {
		const flow = "magic-same-origin";
		const stub = flowStub(flow);
		await stub.create(context("alpha", ALPHA_REDIRECT));
		await stub.setChallenge(EMAIL, await hashSecret("222222", flow), await hashSecret("tok", flow));

		const res = await exports.default.fetch(`${ISSUER}/magic`, {
			method: "POST",
			redirect: "manual",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				"Sec-Fetch-Site": "same-origin",
			},
			body: new URLSearchParams({ flow, token: "tok" }).toString(),
		});

		expect(res.status).toBe(302);
		expect(res.headers.get("Location")).toContain("https://alpha.test/");
	});

	it("refuses a submission whose page belongs to a different flow", async () => {
		// Flow substitution. One flow cookie serves the whole issuer and every render overwrites it,
		// so another tab can repoint it between render and click — completing a *different* tenant's
		// sign-in from a page branded for this one, with no email sent and nothing on screen naming
		// the site that benefits.
		const victim = "flow-page";
		const attacker = "flow-cookie";
		await flowStub(victim).create(context("alpha", ALPHA_REDIRECT));
		await flowStub(attacker).create(context("beta", BETA_REDIRECT));

		const res = await postForm(
			`${ISSUER}/authorize`,
			{ step: "change_email", flow: victim }, // the page the human is looking at
			`__Host-wp_auth_flow=${attacker}`, // what another tab left in the cookie
		);

		expect(res.status).toBe(400);
		const html = await res.text();
		expect(html).toContain("Start again");
		expect(html).not.toContain("Beta Site");
	});

	it("refuses a client_secret rather than ignoring one", async () => {
		// Discovery advertises auth method "none". Silently accepting a secret would let an operator
		// believe JWT_AUTH_CLIENT_SECRET adds a factor when it does nothing at all.
		const code = await mintCodeFor("secret-tok", "alpha", ALPHA_REDIRECT);
		const res = await postForm(`${ISSUER}/token`, {
			grant_type: "authorization_code",
			code,
			redirect_uri: ALPHA_REDIRECT,
			code_verifier: CODE_VERIFIER,
			client_id: "alpha",
			client_secret: "hunter2",
		});

		expect(res.status).toBe(401);
		expect((await res.json()) as { error: string }).toMatchObject({ error: "invalid_client" });
	});

	it("still accepts the empty client_secret the setup instructions print", async () => {
		const code = await mintCodeFor("secret-empty", "alpha", ALPHA_REDIRECT);
		const res = await postForm(`${ISSUER}/token`, {
			grant_type: "authorization_code",
			code,
			redirect_uri: ALPHA_REDIRECT,
			code_verifier: CODE_VERIFIER,
			client_id: "alpha",
			client_secret: "",
		});

		expect(res.status).toBe(200);
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
			{ step: "continue_sso", flow: flowIdFrom(flowCookie) },
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
