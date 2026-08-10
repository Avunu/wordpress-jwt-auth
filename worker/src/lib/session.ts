import type { ProviderConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
import type { UserSession } from "../session-do";
import { clearCookie, getCookie, setCookie } from "./http";
import { randomHex } from "./util";

/** Host-only SSO cookie. See FLOW_COOKIE in http.ts for why the `__Host-` prefix is used. */
export const SSO_COOKIE = "__Host-sso";

export interface ActiveSession {
	id: string;
	email: string;
	linkedTenants: readonly string[];
	/** Set-Cookie that rolls the browser's copy forward in step with the DO's idle window. */
	cookie: string;
}

function stubFor(
	namespace: DurableObjectNamespace<UserSession>,
	sessionId: string,
): DurableObjectStub<UserSession> {
	return namespace.get(namespace.idFromName(sessionId));
}

function cookieFor(provider: ProviderConfig, sessionId: string): string {
	return setCookie(SSO_COOKIE, sessionId, Math.floor(provider.sessionIdleMs / 1000));
}

/**
 * Read and extend the SSO session the request's cookie names. Null when there is no cookie, the
 * session has lapsed, or the deployment has no SSO_SESSION binding — every caller treats that
 * uniformly as "this browser must verify an email".
 */
export async function readSession(
	request: Request,
	env: AuthWorkerEnv,
	provider: ProviderConfig,
): Promise<ActiveSession | null> {
	const namespace = env.SSO_SESSION;
	const sessionId = getCookie(request, SSO_COOKIE);
	if (!namespace || !sessionId) {
		return null;
	}
	const view = await stubFor(namespace, sessionId).touch();
	if (!view) {
		return null;
	}
	return {
		id: sessionId,
		email: view.email,
		linkedTenants: view.linkedTenants,
		cookie: cookieFor(provider, sessionId),
	};
}

/** Record that this browser has now signed into `clientId`, so later visits can be silent. */
export async function linkSession(
	env: AuthWorkerEnv,
	provider: ProviderConfig,
	sessionId: string,
	clientId: string,
): Promise<ActiveSession | null> {
	const namespace = env.SSO_SESSION;
	if (!namespace) {
		return null;
	}
	const view = await stubFor(namespace, sessionId).link(clientId);
	if (!view) {
		return null;
	}
	return {
		id: sessionId,
		email: view.email,
		linkedTenants: view.linkedTenants,
		cookie: cookieFor(provider, sessionId),
	};
}

/**
 * Begin a session for an identity that has just proved control of its inbox. Returns the Set-Cookie
 * to attach to the redirect back to WordPress, or null when the deployment has no SSO binding.
 */
export async function startSession(
	env: AuthWorkerEnv,
	provider: ProviderConfig,
	email: string,
	clientId: string,
): Promise<string | null> {
	const namespace = env.SSO_SESSION;
	if (!namespace) {
		return null;
	}
	const sessionId = randomHex(32);
	await stubFor(namespace, sessionId).start(
		email,
		clientId,
		provider.sessionIdleMs,
		provider.sessionAbsoluteMs,
	);
	return cookieFor(provider, sessionId);
}

/**
 * Sign out of the provider itself. Returns the clearing Set-Cookie unconditionally — even if the
 * session is already gone, the browser should stop presenting a stale id.
 */
export async function endSession(request: Request, env: AuthWorkerEnv): Promise<string> {
	const namespace = env.SSO_SESSION;
	const sessionId = getCookie(request, SSO_COOKIE);
	if (namespace && sessionId) {
		await stubFor(namespace, sessionId).end();
	}
	return clearCookie(SSO_COOKIE);
}
