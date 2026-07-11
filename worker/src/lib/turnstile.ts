import { TurnstileResult } from "../schemas";

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/**
 * Server-side Cloudflare Turnstile verification. Fails closed: any transport error, non-2xx
 * response, malformed body, or `success: false` returns false.
 */
export async function verifyTurnstile(
	token: string,
	secret: string,
	remoteIp: string | null,
): Promise<boolean> {
	const body = new FormData();
	body.append("secret", secret);
	body.append("response", token);
	if (remoteIp) {
		body.append("remoteip", remoteIp);
	}

	let response: Response;
	try {
		response = await fetch(SITEVERIFY_URL, { method: "POST", body });
	} catch {
		return false;
	}
	if (!response.ok) {
		return false;
	}

	let json: unknown;
	try {
		json = await response.json();
	} catch {
		return false;
	}
	const parsed = TurnstileResult.safeParse(json);
	return parsed.success && parsed.data.success;
}
