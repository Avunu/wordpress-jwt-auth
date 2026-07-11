export const FLOW_COOKIE = "wp_auth_flow";

export function json(data: unknown, status = 200): Response {
	return Response.json(data, { status });
}

/**
 * 302 built by hand — Response.redirect() returns an immutable response whose headers can't be
 * extended (the PoC's Set-Cookie append silently no-oped for that reason).
 */
export function redirect(location: string, extraHeaders: Record<string, string> = {}): Response {
	return new Response(null, {
		status: 302,
		headers: { Location: location, ...extraHeaders },
	});
}

export function setCookie(name: string, value: string, maxAgeSeconds: number): string {
	const attrs = [
		`${name}=${encodeURIComponent(value)}`,
		"Path=/",
		"HttpOnly",
		"Secure",
		"SameSite=Lax",
		`Max-Age=${maxAgeSeconds}`,
	];
	return attrs.join("; ");
}

export function clearCookie(name: string): string {
	return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function getCookie(request: Request, name: string): string | null {
	const header = request.headers.get("Cookie");
	if (!header) {
		return null;
	}
	for (const part of header.split(";")) {
		const eq = part.indexOf("=");
		if (eq === -1) {
			continue;
		}
		if (part.slice(0, eq).trim() === name) {
			return decodeURIComponent(part.slice(eq + 1).trim());
		}
	}
	return null;
}

export async function readForm(request: Request): Promise<Record<string, string>> {
	const fd = await request.formData();
	const out: Record<string, string> = {};
	for (const [k, v] of fd) {
		if (typeof v === "string") {
			out[k] = v;
		}
	}
	return out;
}

export function clientIp(request: Request): string | null {
	return request.headers.get("CF-Connecting-IP");
}

interface Limiter {
	limit: (options: { key: string }) => Promise<{ success: boolean }>;
}

/** Check a rate-limit binding, failing OPEN on any error (Turnstile is the primary gate). */
export async function underLimit(limiter: Limiter | undefined, key: string): Promise<boolean> {
	if (!limiter) {
		return true;
	}
	try {
		const { success } = await limiter.limit({ key });
		return success;
	} catch {
		return true;
	}
}
