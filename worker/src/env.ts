/// <reference types="@cloudflare/workers-types" />
import type { LoginFlow } from "./flow-do";
import type { UserSession } from "./session-do";

/**
 * Bindings + configuration every deployment provides. Config values may arrive as committed `vars`
 * or as per-Worker secrets — the worker reads them identically through `env`, so this interface
 * makes no distinction. Consumers (thin wrappers) supply these via their `wrangler.jsonc`
 * bindings/vars plus `wrangler secret` for the sensitive ones.
 */
export interface AuthWorkerEnv {
	// --- Bindings ---
	/** Native Email Sending binding. */
	EMAIL: SendEmail;
	/** One LoginFlow Durable Object instance per in-progress login. */
	LOGIN_FLOW: DurableObjectNamespace<LoginFlow>;
	/**
	 * One UserSession instance per signed-in browser, backing cross-site SSO. Optional: a deployment
	 * without this binding simply asks for an email + PIN every time, so single-site wrappers can
	 * adopt a new core version without a Durable Object migration.
	 */
	SSO_SESSION?: DurableObjectNamespace<UserSession>;
	/** Optional per-email send throttle. */
	RL_EMAIL?: RateLimit;
	/** Optional per-IP throttle. */
	RL_IP?: RateLimit;

	// --- Provider config (committed vars or secrets) ---
	ISSUER: string;
	FROM_EMAIL: string;
	FROM_NAME?: string;
	TURNSTILE_SITE_KEY: string;
	TURNSTILE_SECRET_KEY: string;
	SIGNING_KEY: string;
	/** Rolling SSO inactivity window in days (default 14). */
	SESSION_IDLE_DAYS?: string;
	/** Absolute SSO session lifetime in days (default 90). */
	SESSION_ABSOLUTE_DAYS?: string;

	// --- Tenants ---
	/**
	 * JSON array of tenant objects. Ignored when the wrapper passes tenants to createAuthWorker(),
	 * which is the preferred route — bundled JSON has no var size limit and is typed at build time.
	 */
	TENANTS?: string;

	// --- Legacy single-tenant config ---
	/** Pre-fleet deployments describe their one tenant with these two. Superseded by TENANTS. */
	CLIENT_ID?: string;
	ALLOWED_REDIRECT_URIS?: string;
}
