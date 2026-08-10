import type { ProviderConfig } from "../config";
import { json } from "../lib/http";
import { publicJwks } from "../lib/jwt";

/**
 * OIDC discovery document. Only issuer/authorization/token/jwks are read by the plugin; the rest
 * are standard, harmless, and make the endpoint recognisably OIDC.
 *
 * There is one document for the whole fleet: every tenant shares this issuer, these endpoints, and
 * this key set. What differs per tenant is the audience of the token they get back, not the
 * metadata they discover.
 */
export function handleDiscovery(provider: ProviderConfig): Response {
	return json({
		issuer: provider.issuer,
		authorization_endpoint: `${provider.issuer}/authorize`,
		token_endpoint: `${provider.issuer}/token`,
		jwks_uri: `${provider.issuer}/.well-known/jwks.json`,
		end_session_endpoint: `${provider.issuer}/logout`,
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		id_token_signing_alg_values_supported: ["RS256"],
		scopes_supported: ["openid", "email", "profile"],
		code_challenge_methods_supported: ["S256"],
		subject_types_supported: ["public"],
		token_endpoint_auth_methods_supported: ["none"],
	});
}

export async function handleJwks(provider: ProviderConfig): Promise<Response> {
	const jwks = await publicJwks(provider);
	// Public keys are stable; let WordPress and CDNs cache them.
	return Response.json(jwks, {
		headers: { "Cache-Control": "public, max-age=3600" },
	});
}
