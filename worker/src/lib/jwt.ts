import { SignJWT, importPKCS8, exportJWK, calculateJwkThumbprint } from "jose";
import type { JWK } from "jose";
import type { AppConfig } from "../config";
import type { Identity } from "../schemas";

interface KeyBundle {
	pem: string;
	privateKey: CryptoKey;
	/** Public JWK ready to publish (kty, n, e + alg/use/kid). */
	publicJwk: JWK;
	kid: string;
}

// Deployment-scoped, not request-scoped: the signing key is identical for every request
// Of a given deployment. Memoised (keyed by the PEM) so we import + thumbprint once per
// Isolate rather than on every sign/JWKS call. Recomputes only if the secret changes.
let bundleCache: KeyBundle | null = null;

async function getKeyBundle(pem: string): Promise<KeyBundle> {
	if (bundleCache && bundleCache.pem === pem) {
		return bundleCache;
	}

	const privateKey = await importPKCS8(pem, "RS256", { extractable: true });
	const full = await exportJWK(privateKey);
	if (!full.kty || !full.n || !full.e) {
		throw new Error("SIGNING_KEY did not yield an RSA public modulus/exponent");
	}
	// Keep only the public members — never publish d/p/q/dp/dq/qi.
	const publicOnly: JWK = { kty: full.kty, n: full.n, e: full.e };
	const kid = await calculateJwkThumbprint(publicOnly, "sha256");
	const publicJwk: JWK = { ...publicOnly, alg: "RS256", use: "sig", kid };

	bundleCache = { pem, privateKey, publicJwk, kid };
	return bundleCache;
}

/** The JWKS document served at /.well-known/jwks.json, derived from the private key. */
export async function publicJwks(config: AppConfig): Promise<{ keys: JWK[] }> {
	const { publicJwk } = await getKeyBundle(config.signingKeyPem);
	return { keys: [publicJwk] };
}

/** Mint a signed RS256 id_token for a resolved identity. */
export async function signIdToken(
	config: AppConfig,
	identity: Identity,
	ttlSeconds = 300,
): Promise<string> {
	const { privateKey, kid } = await getKeyBundle(config.signingKeyPem);
	const now = Math.floor(Date.now() / 1000);

	const claims: Record<string, string> = { email: identity.email };
	if (identity.name) {
		claims["name"] = identity.name;
	}
	if (identity.given_name) {
		claims["given_name"] = identity.given_name;
	}
	if (identity.family_name) {
		claims["family_name"] = identity.family_name;
	}

	return new SignJWT(claims)
		.setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
		.setIssuer(config.issuer)
		.setSubject(identity.sub)
		.setAudience(config.clientId)
		.setIssuedAt(now)
		.setExpirationTime(now + ttlSeconds)
		.sign(privateKey);
}
