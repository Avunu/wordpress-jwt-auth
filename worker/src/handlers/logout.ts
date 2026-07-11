import type { AppConfig } from "../config";
import { redirect } from "../lib/http";
import { errorPage } from "../ui";

/**
 * GET /logout — the OIDC end_session_endpoint. The worker holds no session of its own (WordPress
 * owns the auth cookie), so this only bounces the browser back to an allowed post-logout URL. The
 * target's origin must match one of our allowed redirect URIs to prevent this from being used as an
 * open redirector.
 */
export function handleLogout(request: Request, config: AppConfig): Response {
	const url = new URL(request.url);
	const target = url.searchParams.get("post_logout_redirect_uri");
	if (!target) {
		return errorPage({ title: "Signed out", message: "You have been signed out.", status: 200 });
	}

	let allowed = false;
	try {
		const targetOrigin = new URL(target).origin;
		allowed = config.allowedRedirectUris.some((uri) => {
			try {
				return new URL(uri).origin === targetOrigin;
			} catch {
				return false;
			}
		});
	} catch {
		allowed = false;
	}

	if (!allowed) {
		return errorPage({ title: "Signed out", message: "You have been signed out.", status: 200 });
	}
	return redirect(target);
}
