/// <reference types="@cloudflare/workers-types" />
import { loadConfig, ConfigError } from "./config";
import type { AppConfig } from "./config";
import type { AuthWorkerEnv } from "./env";
import { handleDiscovery, handleJwks } from "./handlers/discovery";
import { handleAuthorizeGet, handleAuthorizePost } from "./handlers/authorize";
import { handleMagicGet, handleMagicPost } from "./handlers/magic";
import { handleToken } from "./handlers/token";
import { handleLogout } from "./handlers/logout";

// Public package surface: the fetch handler (default), the Durable Object class (which the
// Thin wrapper must re-export from its entry so wrangler can bind it), and the env contract.
export { LoginFlow } from "./flow-do";
export type { AuthWorkerEnv } from "./env";
export type { AppConfig } from "./config";

/** Method + path → handler. Config is loaded once per request and passed in. */
async function route(request: Request, env: AuthWorkerEnv, config: AppConfig): Promise<Response> {
	const url = new URL(request.url);
	const { pathname } = url;
	const { method } = request;

	if (method === "GET" && pathname === "/.well-known/openid-configuration") {
		return handleDiscovery(config);
	}
	if (method === "GET" && pathname === "/.well-known/jwks.json") {
		return handleJwks(config);
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
			return handleMagicPost(request, env);
		}
	}
	if (method === "POST" && pathname === "/token") {
		return handleToken(request, env, config);
	}
	if (method === "GET" && pathname === "/logout") {
		return handleLogout(request, config);
	}

	return new Response("Not found", { status: 404 });
}

export default {
	async fetch(request: Request, env: AuthWorkerEnv, _ctx: ExecutionContext): Promise<Response> {
		let config: AppConfig;
		try {
			config = loadConfig(env);
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
} satisfies ExportedHandler<AuthWorkerEnv>;
