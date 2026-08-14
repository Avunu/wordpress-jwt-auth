/// <reference types="@cloudflare/workers-types" />
import { loadConfig, ConfigError } from "./config";
import type { WorkerConfig } from "./config";
import type { AuthWorkerEnv } from "./env";
import { handleDiscovery, handleJwks } from "./handlers/discovery";
import { handleAuthorizeGet, handleAuthorizePost } from "./handlers/authorize";
import { handleMagicGet, handleMagicPost } from "./handlers/magic";
import { handleToken } from "./handlers/token";
import { handleLogout } from "./handlers/logout";

// Public package surface: the worker factory, the ready-made env-driven handler (default), the
// Durable Object classes (which the thin wrapper must re-export from its entry so wrangler can
// bind them), and the config contracts.
export { LoginFlow } from "./flow-do";
export { UserSession } from "./session-do";
export { LoginGuard } from "./guard-do";
export { Tenant, TenantRegistry } from "./tenant";
export type { AuthWorkerEnv } from "./env";
export type { ProviderConfig, WorkerConfig } from "./config";

/** Method + path → handler. Config is loaded once per request and passed in. */
async function route(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const { pathname } = url;
	const { method } = request;

	if (method === "GET" && pathname === "/.well-known/openid-configuration") {
		return handleDiscovery(config.provider);
	}
	if (method === "GET" && pathname === "/.well-known/jwks.json") {
		return handleJwks(config.provider);
	}
	if (pathname === "/authorize") {
		if (method === "GET") {
			return handleAuthorizeGet(request, env, config);
		}
		if (method === "POST") {
			return handleAuthorizePost(request, env, config);
		}
	}
	if (pathname === "/magic") {
		if (method === "GET") {
			return handleMagicGet(request, env, config);
		}
		if (method === "POST") {
			return handleMagicPost(request, env, config);
		}
	}
	if (method === "POST" && pathname === "/token") {
		return handleToken(request, env, config);
	}
	if (method === "GET" && pathname === "/logout") {
		return handleLogout(request, env, config);
	}

	return new Response("Not found", { status: 404 });
}

export interface AuthWorkerOptions {
	/**
	 * The fleet this worker serves, validated against the Tenant schema at first use. Supplying it
	 * here is preferred over the TENANTS var: bundled JSON has no var size limit, is reviewable in
	 * git, and fails the build rather than the request when it is malformed. Omit for a deployment
	 * that describes its tenants through env instead.
	 */
	tenants?: readonly unknown[];
}

/**
 * Build the Worker fetch handler for a fleet.
 *
 * ```ts
 * import tenants from "./tenants.json";
 * export { LoginFlow, UserSession, LoginGuard } from "@avunu/jwt-auth-worker";
 * export default createAuthWorker({ tenants });
 * ```
 */
export function createAuthWorker(options: AuthWorkerOptions = {}): ExportedHandler<AuthWorkerEnv> {
	return {
		async fetch(request: Request, env: AuthWorkerEnv, _ctx: ExecutionContext): Promise<Response> {
			let config: WorkerConfig;
			try {
				config = loadConfig(env, options.tenants);
			} catch (error) {
				if (error instanceof ConfigError) {
					// Misconfigured deployment: refuse rather than mint tokens with wrong iss/aud/key.
					console.error(JSON.stringify({ event: "config_error", message: error.message }));
					return new Response("Auth provider is not configured correctly.", { status: 500 });
				}
				throw error;
			}

			try {
				return await route(request, env, config);
			} catch (error) {
				console.error(
					JSON.stringify({
						event: "unhandled_error",
						path: new URL(request.url).pathname,
						message: error instanceof Error ? error.message : String(error),
					}),
				);
				return new Response("Internal error", { status: 500 });
			}
		},
	};
}

/**
 * The env-driven handler, for wrappers that pass their configuration entirely through wrangler —
 * including every pre-fleet single-site deployment, which keeps working unchanged.
 */
export default createAuthWorker();
