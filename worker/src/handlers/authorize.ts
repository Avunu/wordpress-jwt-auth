import type { AppConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
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
import { generateMagicToken, generatePin, hashSecret } from "../lib/otp";
import { randomHex, sha256Hex } from "../lib/util";
import { verifyTurnstile } from "../lib/turnstile";
import { sendLoginEmail } from "../lib/email";
import { emailFormPage, errorPage, pinFormPage } from "../ui";

const FLOW_TTL_SECONDS = 600;
const PIN_TTL_MINUTES = 5;

/** GET /authorize — validate the OIDC request, open a flow, render the email form. */
export async function handleAuthorizeGet(
	request: Request,
	env: AuthWorkerEnv,
	config: AppConfig,
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

	// Never redirect anywhere we weren't told to trust.
	if (p.client_id !== config.clientId || !config.allowedRedirectUris.includes(p.redirect_uri)) {
		return errorPage({
			title: "Unrecognised sign-in request",
			message: "This sign-in request is not authorised for this provider.",
			status: 400,
		});
	}

	const flowId = randomHex(16);
	await getFlowStub(env, flowId).create({
		clientId: p.client_id,
		redirectUri: p.redirect_uri,
		wpState: p.state,
		scope: p.scope,
		codeChallenge: p.code_challenge,
		createdAt: Date.now(),
	});

	const res = emailFormPage({ siteLabel: config.issuerHost, siteKey: config.turnstileSiteKey });
	res.headers.append("Set-Cookie", setCookie(FLOW_COOKIE, flowId, FLOW_TTL_SECONDS));
	return res;
}

/** POST /authorize — request_code (send email) or verify_code (check PIN → mint code). */
export async function handleAuthorizePost(
	request: Request,
	env: AuthWorkerEnv,
	config: AppConfig,
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

	const form = AuthorizeForm.safeParse(await readForm(request));
	if (!form.success) {
		return emailFormPage({
			siteLabel: config.issuerHost,
			siteKey: config.turnstileSiteKey,
			error: "Please check your details and try again.",
			status: 400,
		});
	}

	if (form.data.action === "request_code") {
		return requestCode(
			env,
			config,
			stub,
			flowId,
			form.data.email,
			form.data["cf-turnstile-response"],
			request,
		);
	}
	if (form.data.action === "change_email") {
		// Re-render the email form for this same flow so the user can enter a different address.
		// Nothing is sent; a later request_code overwrites the challenge and resets attempts.
		return emailFormPage({
			siteLabel: config.issuerHost,
			siteKey: config.turnstileSiteKey,
		});
	}
	return verifyCode(config, stub, flowId, form.data.pin);
}

async function requestCode(
	env: AuthWorkerEnv,
	config: AppConfig,
	stub: ReturnType<typeof getFlowStub>,
	flowId: string,
	email: string,
	turnstileToken: string,
	request: Request,
): Promise<Response> {
	const renderError = (error: string, status = 400): Response =>
		emailFormPage({
			siteLabel: config.issuerHost,
			siteKey: config.turnstileSiteKey,
			error,
			status,
		});

	const human = await verifyTurnstile(turnstileToken, config.turnstileSecretKey, clientIp(request));
	if (!human) {
		return renderError("Verification failed. Please try again.", 403);
	}

	const emailHash = await sha256Hex(email);
	const ip = clientIp(request) ?? "noip";
	const withinLimits =
		(await underLimit(env.RL_EMAIL, `${config.issuerHost}:${emailHash}`)) &&
		(await underLimit(env.RL_IP, `${config.issuerHost}:${ip}`));
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

	const magicUrl = `${config.issuer}/magic?flow=${encodeURIComponent(flowId)}&token=${encodeURIComponent(magicToken)}`;
	try {
		await sendLoginEmail(env, config, {
			to: email,
			pin,
			magicUrl,
			siteLabel: config.issuerHost,
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

	return pinFormPage({
		siteLabel: config.issuerHost,
		email,
		notice: "Check your inbox for the 6-digit code.",
	});
}

async function verifyCode(
	config: AppConfig,
	stub: ReturnType<typeof getFlowStub>,
	flowId: string,
	pin: string,
): Promise<Response> {
	const submittedHash = await hashSecret(pin, flowId);
	const result = await stub.verifyPin(submittedHash);

	if (result.ok) {
		return finishRedirect(result.redirectUri, result.code, result.state);
	}

	switch (result.reason) {
		case "invalid": {
			return pinFormPage({
				siteLabel: config.issuerHost,
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
			});
		}
		case "expired": {
			return errorPage({
				title: "Code expired",
				message: "That code has expired. Return to the site and sign in again.",
				status: 410,
			});
		}
		default: {
			return sessionExpired();
		}
	}
}

/** Build the success redirect back to WordPress with code + state. */
export function finishRedirect(redirectUri: string, code: string, state: string): Response {
	const target = new URL(redirectUri);
	target.searchParams.set("code", code);
	target.searchParams.set("state", state);
	return redirect(target.toString(), { "Set-Cookie": clearCookie(FLOW_COOKIE) });
}

function sessionExpired(): Response {
	return errorPage({
		title: "Sign-in session expired",
		message: "This sign-in session has expired. Please return to the site and try again.",
		status: 400,
	});
}
