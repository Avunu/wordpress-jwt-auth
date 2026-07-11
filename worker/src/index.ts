/// <reference types="@cloudflare/workers-types" />
import { loadConfig, ConfigError, type AppConfig } from "./config";
import type { AuthWorkerEnv } from "./env";
import { handleDiscovery, handleJwks } from "./handlers/discovery";
import { handleAuthorizeGet, handleAuthorizePost } from "./handlers/authorize";
import { handleMagicGet, handleMagicPost } from "./handlers/magic";
import { handleToken } from "./handlers/token";
import { handleLogout } from "./handlers/logout";

// Public package surface: the fetch handler (default), the Durable Object class (which the
// thin wrapper must re-export from its entry so wrangler can bind it), and the env contract.
export { LoginFlow } from "./flow-do";
export type { AuthWorkerEnv } from "./env";
export type { AppConfig } from "./config";

/** Method + path → handler. Config is loaded once per request and passed in. */
async function route(request: Request, env: AuthWorkerEnv, config: AppConfig): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;

  if (method === "GET" && pathname === "/.well-known/openid-configuration") {
    return handleDiscovery(config);
  }
  if (method === "GET" && pathname === "/.well-known/jwks.json") {
    return handleJwks(config);
  }
  if (pathname === "/authorize") {
    if (method === "GET") return handleAuthorizeGet(request, env, config);
    if (method === "POST") return handleAuthorizePost(request, env, config);
  }
  if (pathname === "/magic") {
    if (method === "GET") return handleMagicGet(request, env, config);
    if (method === "POST") return handleMagicPost(request, env);
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
    } catch (err) {
      if (err instanceof ConfigError) {
        // Misconfigured deployment: refuse rather than mint tokens with wrong iss/aud/key.
        console.error(JSON.stringify({ event: "config_error", message: err.message }));
        return new Response("Auth provider is not configured correctly.", { status: 500 });
      }
      throw err;
    }

    try {
      return await route(request, env, config);
    } catch (err) {
      console.error(
        JSON.stringify({
          event: "unhandled_error",
          path: new URL(request.url).pathname,
          message: err instanceof Error ? err.message : String(err),
        }),
      );
      return new Response("Internal error", { status: 500 });
    }
  },
} satisfies ExportedHandler<AuthWorkerEnv>;
