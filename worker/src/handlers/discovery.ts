import type { AppConfig } from "../config";
import { json } from "../lib/http";
import { publicJwks } from "../lib/jwt";

/**
 * OIDC discovery document. Only issuer/authorization/token/jwks are read by the plugin; the rest
 * are standard, harmless, and make the endpoint recognisably OIDC.
 */
export function handleDiscovery(config: AppConfig): Response {
	return json({
		issuer: config.issuer,
		authorization_endpoint: `${config.issuer}/authorize`,
		token_endpoint: `${config.issuer}/token`,
		jwks_uri: `${config.issuer}/.well-known/jwks.json`,
		end_session_endpoint: `${config.issuer}/logout`,
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		id_token_signing_alg_values_supported: ["RS256"],
		scopes_supported: ["openid", "email", "profile"],
		code_challenge_methods_supported: ["S256"],
		subject_types_supported: ["public"],
		token_endpoint_auth_methods_supported: ["none"],
	});
}

export async function handleJwks(config: AppConfig): Promise<Response> {
	const jwks = await publicJwks(config);
	// Public keys are stable; let WordPress and CDNs cache them.
	return Response.json(jwks, {
		headers: { "Cache-Control": "public, max-age=3600" },
	});
}
