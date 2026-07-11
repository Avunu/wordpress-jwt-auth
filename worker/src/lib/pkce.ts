import { sha256Base64Url, timingSafeEqual } from "./util";

/**
 * Verify an RFC 7636 PKCE S256 challenge: BASE64URL(SHA-256(code_verifier)) === code_challenge. The
 * plugin always uses S256 (never "plain"), so that is all we support.
 */
export async function verifyPkceS256(
	codeVerifier: string,
	codeChallenge: string,
): Promise<boolean> {
	const computed = await sha256Base64Url(codeVerifier);
	return timingSafeEqual(computed, codeChallenge);
}
