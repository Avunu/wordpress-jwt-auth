import type { WorkerConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
import { getFlowStub } from "../lib/flow";
import { hashSecret } from "../lib/otp";
import { readForm } from "../lib/http";
import { magicConfirmPage, errorPage, respond } from "../ui";
import { alreadyUsed, completeSignIn } from "./authorize";

/** Every dead end on this endpoint says the same thing: the link is no longer good. */
function linkExpired(tenant: Parameters<typeof alreadyUsed>[0] | null = null) {
	return errorPage({
		title: "Link expired",
		message: "This sign-in link has expired. Return to the site and try again.",
		status: 410,
		tenant,
	});
}

/**
 * GET /magic — render the confirm page ONLY. It never consumes the token, so an email security
 * scanner that auto-fetches the link does no harm. The human presses the button, which POSTs back
 * to actually sign in.
 */
export async function handleMagicGet(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const flow = url.searchParams.get("flow");
	const token = url.searchParams.get("token");
	if (!flow || !token) {
		return respond(
			request,
			errorPage({ title: "Invalid link", message: "This sign-in link is incomplete." }),
		);
	}

	// Confirm the flow is still alive so we don't present a dead confirm page.
	const context = await getFlowStub(env, flow).getContext();
	if (!context) {
		return respond(request, linkExpired());
	}

	return respond(
		request,
		magicConfirmPage({ tenant: config.tenants.get(context.clientId), flow, token }),
	);
}

/**
 * A cross-site POST here is never a human pressing the button on our confirm page.
 *
 * This endpoint is deliberately cookie-independent, so `SameSite` protects nothing and the 256-bit
 * token is the whole authenticator — which means anyone _holding_ a token can have someone else's
 * browser spend it. An attacker who starts a sign-in with their own address, does not click their
 * own link, and auto-submits it from a page the victim loads gets a code minted into the victim's
 * browser _and_ a fresh SSO cookie bound to the attacker's identity, good for the full idle window.
 * The victim is then silently signed in as the attacker everywhere in the fleet.
 *
 * Requiring same-origin costs the documented cross-device case nothing: the confirm page is served
 * from this origin to whatever browser opened the link, so the POST that follows is same-origin in
 * that browser. `Sec-Fetch-Site: none` covers a direct navigation, and the Origin comparison is the
 * fallback for clients that do not send Fetch Metadata.
 */
function isSameOrigin(request: Request, issuer: string): boolean {
	const site = request.headers.get("Sec-Fetch-Site");
	if (site) {
		return site === "same-origin" || site === "none";
	}
	const origin = request.headers.get("Origin");
	return origin === null || origin === issuer;
}

/**
 * POST /magic — the real human click. Consume the token and redirect back to WordPress.
 *
 * Cookie-independent by design so the link works in a different browser or on another device; the
 * tenant therefore comes from the flow record rather than from a cookie or the form.
 */
export async function handleMagicPost(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	if (!isSameOrigin(request, config.provider.issuer)) {
		console.log(
			JSON.stringify({
				event: "magic_cross_site_post",
				fetchSite: request.headers.get("Sec-Fetch-Site"),
				origin: request.headers.get("Origin"),
			}),
		);
		return respond(request, linkExpired());
	}

	const form = await readForm(request);
	const { flow } = form;
	const { token } = form;
	if (!flow || !token) {
		return respond(
			request,
			errorPage({ title: "Invalid link", message: "This sign-in link is incomplete." }),
		);
	}

	const stub = getFlowStub(env, flow);
	const context = await stub.getContext();
	const tenant = context ? config.tenants.get(context.clientId) : null;
	if (!tenant) {
		return respond(request, linkExpired());
	}

	const submittedHash = await hashSecret(token, flow);
	const result = await stub.verifyMagic(submittedHash);

	if (result.ok) {
		return completeSignIn(request, env, config.provider, tenant, result);
	}

	switch (result.reason) {
		case "already_used": {
			// Clicking the link a second time, or a mail client that pre-fetched and then the human
			// clicked. The sign-in already happened; say so instead of implying the link is broken.
			return respond(request, alreadyUsed(tenant));
		}
		case "expired": {
			return respond(request, linkExpired(tenant));
		}
		case "locked": {
			return respond(
				request,
				errorPage({
					title: "Too many attempts",
					message: "Return to the site to start over.",
					status: 429,
					tenant,
				}),
			);
		}
		default: {
			return respond(
				request,
				errorPage({
					title: "Invalid link",
					message: "This sign-in link is no longer valid. Return to the site and try again.",
					status: 400,
					tenant,
				}),
			);
		}
	}
}
