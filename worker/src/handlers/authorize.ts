import type { ProviderConfig, WorkerConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
import type { LoginFlow, MintedCode } from "../flow-do";
import type { FlowContext } from "../schemas";
import type { Tenant } from "../tenant";
import { AuthorizeForm, AuthorizeParams } from "../schemas";
import {
	FLOW_COOKIE,
	clearCookie,
	clientIp,
	getCookie,
	readForm,
	redirect,
	setCookie,
	underLimit,
} from "../lib/http";
import { getFlowStub } from "../lib/flow";
import { SSO_COOKIE, linkSession, readSession, startSession } from "../lib/session";
import { generateMagicToken, generatePin, hashSecret } from "../lib/otp";
import { randomHex, sha256Hex } from "../lib/util";
import { verifyTurnstile } from "../lib/turnstile";
import { sendLoginEmail } from "../lib/email";
import { continuePage, emailFormPage, errorPage, pinFormPage } from "../ui";

const FLOW_TTL_SECONDS = 600;
const PIN_TTL_MINUTES = 5;

type FlowStub = DurableObjectStub<LoginFlow>;

/** GET /authorize — validate the OIDC request, open a flow, then ask for as little as possible. */
export async function handleAuthorizeGet(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const parsed = AuthorizeParams.safeParse(Object.fromEntries(url.searchParams));
	if (!parsed.success) {
		return errorPage({
			title: "Invalid sign-in request",
			message: "The sign-in link was malformed. Please return to the site and try again.",
		});
	}
	const p = parsed.data;

	// Resolve who is asking before anything else, and never redirect anywhere that tenant hasn't
	// registered. An unknown client and a redirect URI belonging to a *different* tenant are the
	// same answer: this request is not authorised.
	const tenant = config.tenants.get(p.client_id);
	if (!tenant || !tenant.redirectUris.includes(p.redirect_uri)) {
		return errorPage({
			title: "Unrecognised sign-in request",
			message: "This sign-in request is not authorised for this provider.",
			status: 400,
		});
	}

	const flowId = randomHex(16);
	const context: FlowContext = {
		clientId: p.client_id,
		redirectUri: p.redirect_uri,
		wpState: p.state,
		scope: p.scope,
		codeChallenge: p.code_challenge,
		createdAt: Date.now(),
	};
	const stub = getFlowStub(env, flowId);

	const skipSso = p.prompt === "login" || !tenant.sso;
	const session = skipSso ? null : await readSession(request, env, config.provider);

	// A site this browser has signed into before: nothing left to prove, mint and go.
	if (session?.linkedTenants.includes(tenant.clientId)) {
		const minted = await stub.createAndComplete(context, session.email);
		return finishRedirect(minted, [session.cookie]);
	}

	await stub.create(context);

	// A live session meeting a new site: confirm rather than silently create an account there.
	const res = session
		? continuePage({ tenant, email: session.email })
		: emailFormPage({ tenant, siteKey: config.provider.turnstileSiteKey });
	res.headers.append("Set-Cookie", setCookie(FLOW_COOKIE, flowId, FLOW_TTL_SECONDS));
	if (session) {
		res.headers.append("Set-Cookie", session.cookie);
	}
	return res;
}

/** POST /authorize — send an email, verify a PIN, or accept the existing SSO session. */
export async function handleAuthorizePost(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	const flowId = getCookie(request, FLOW_COOKIE);
	if (!flowId) {
		return sessionExpired();
	}

	const stub = getFlowStub(env, flowId);
	const context = await stub.getContext();
	if (!context) {
		return sessionExpired();
	}

	// The tenant comes from the flow the cookie points at, never from the submitted form.
	const tenant = config.tenants.get(context.clientId);
	if (!tenant) {
		return errorPage({
			title: "Unrecognised sign-in request",
			message: "This sign-in request is not authorised for this provider.",
			status: 400,
		});
	}

	const form = AuthorizeForm.safeParse(await readForm(request));
	if (!form.success) {
		return emailFormPage({
			tenant,
			siteKey: config.provider.turnstileSiteKey,
			error: "Please check your details and try again.",
			status: 400,
		});
	}

	switch (form.data.action) {
		case "request_code": {
			return requestCode(
				env,
				config,
				stub,
				flowId,
				tenant,
				form.data.email,
				form.data["cf-turnstile-response"],
				request,
			);
		}
		case "change_email": {
			// Re-render the email form for this same flow so the user can enter a different address.
			// Nothing is sent; a later request_code overwrites the challenge and resets attempts.
			// Reached both from the PIN step and from the SSO confirmation, which is the only way to
			// sign in as somebody else without first signing out.
			return emailFormPage({ tenant, siteKey: config.provider.turnstileSiteKey });
		}
		case "continue_sso": {
			return continueSso(request, env, config, stub, tenant);
		}
		default: {
			return verifyCode(env, config, stub, flowId, tenant, form.data.pin);
		}
	}
}

async function requestCode(
	env: AuthWorkerEnv,
	config: WorkerConfig,
	stub: FlowStub,
	flowId: string,
	tenant: Tenant,
	email: string,
	turnstileToken: string,
	request: Request,
): Promise<Response> {
	const { provider } = config;
	const renderError = (error: string, status = 400): Response =>
		emailFormPage({ tenant, siteKey: provider.turnstileSiteKey, error, status });

	const human = await verifyTurnstile(
		turnstileToken,
		provider.turnstileSecretKey,
		clientIp(request),
	);
	if (!human) {
		return renderError("Verification failed. Please try again.", 403);
	}

	// Unprefixed keys: one issuer serves the whole fleet, and an email address is one person
	// wherever they use it, so the throttle belongs to the address and the IP rather than the site.
	const emailHash = await sha256Hex(email);
	const ip = clientIp(request) ?? "noip";
	const withinLimits =
		(await underLimit(env.RL_EMAIL, emailHash)) && (await underLimit(env.RL_IP, ip));
	if (!withinLimits) {
		return renderError("Too many requests. Please wait a minute and try again.", 429);
	}

	const pin = generatePin();
	const magicToken = generateMagicToken();
	const [pinHash, magicHash] = await Promise.all([
		hashSecret(pin, flowId),
		hashSecret(magicToken, flowId),
	]);
	const stored = await stub.setChallenge(email, pinHash, magicHash);
	if (!stored) {
		return sessionExpired();
	}

	const magicUrl = `${provider.issuer}/magic?flow=${encodeURIComponent(flowId)}&token=${encodeURIComponent(magicToken)}`;
	try {
		await sendLoginEmail(env, provider, {
			to: email,
			pin,
			magicUrl,
			tenant,
			ttlMinutes: PIN_TTL_MINUTES,
		});
	} catch (error) {
		console.error(
			JSON.stringify({
				event: "email_send_failed",
				code: (error as { code?: string }).code ?? null,
			}),
		);
		return renderError("We couldn't send the email right now. Please try again.", 502);
	}

	return pinFormPage({ tenant, email, notice: "Check your inbox for the 6-digit code." });
}

async function verifyCode(
	env: AuthWorkerEnv,
	config: WorkerConfig,
	stub: FlowStub,
	flowId: string,
	tenant: Tenant,
	pin: string,
): Promise<Response> {
	const submittedHash = await hashSecret(pin, flowId);
	const result = await stub.verifyPin(submittedHash);

	if (result.ok) {
		return completeSignIn(env, config.provider, tenant, result);
	}

	switch (result.reason) {
		case "invalid": {
			return pinFormPage({
				tenant,
				email: "your email",
				error: "That code is incorrect. Please try again.",
				status: 401,
			});
		}
		case "locked": {
			return errorPage({
				title: "Too many attempts",
				message: "You've entered the wrong code too many times. Return to the site to start over.",
				status: 429,
				tenant,
			});
		}
		case "expired": {
			return errorPage({
				title: "Code expired",
				message: "That code has expired. Return to the site and sign in again.",
				status: 410,
				tenant,
			});
		}
		default: {
			return sessionExpired();
		}
	}
}

/** The "Continue as ..." confirmation: adopt the SSO identity for a site new to this browser. */
async function continueSso(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
	stub: FlowStub,
	tenant: Tenant,
): Promise<Response> {
	const sessionId = getCookie(request, SSO_COOKIE);
	const linked = sessionId
		? await linkSession(env, config.provider, sessionId, tenant.clientId)
		: null;
	if (!linked) {
		// The session lapsed between rendering the page and the click. Ask for an email instead of
		// failing: the flow itself is still good.
		return emailFormPage({ tenant, siteKey: config.provider.turnstileSiteKey });
	}

	const result = await stub.completeWithIdentity(linked.email);
	if (!result.ok) {
		return sessionExpired();
	}
	return finishRedirect(result, [linked.cookie]);
}

/**
 * Finish a _fresh_ authentication: the person just proved control of their inbox, so this is where
 * the SSO session begins and every other site in the fleet becomes a one-click sign-in.
 */
export async function completeSignIn(
	env: AuthWorkerEnv,
	provider: ProviderConfig,
	tenant: Tenant,
	minted: MintedCode,
): Promise<Response> {
	const cookie = await startSession(env, provider, minted.email, tenant.clientId);
	return finishRedirect(minted, cookie ? [cookie] : []);
}

/** Build the success redirect back to WordPress with code + state. */
export function finishRedirect(minted: MintedCode, extraCookies: readonly string[] = []): Response {
	const target = new URL(minted.redirectUri);
	target.searchParams.set("code", minted.code);
	target.searchParams.set("state", minted.state);
	// Built header-by-header because a Response carries multiple Set-Cookie values only via append.
	const res = redirect(target.toString());
	res.headers.append("Set-Cookie", clearCookie(FLOW_COOKIE));
	for (const cookie of extraCookies) {
		res.headers.append("Set-Cookie", cookie);
	}
	return res;
}

function sessionExpired(): Response {
	return errorPage({
		title: "Sign-in session expired",
		message: "This sign-in session has expired. Please return to the site and try again.",
		status: 400,
	});
}
