import type { WorkerConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
import { redirect } from "../lib/http";
import { endSession } from "../lib/session";
import { errorPage } from "../ui";

/**
 * GET /logout — the OIDC end_session_endpoint.
 *
 * This ends the provider's own SSO session, which is what makes signing out mean something across
 * the fleet: WordPress clears its cookie on the site you left, and the next /authorize from any
 * site asks for an email and PIN again rather than silently reusing the old identity. That is also
 * the only way to switch accounts on a shared machine.
 *
 * WordPress sends nothing but `post_logout_redirect_uri`, so the tenant is resolved by matching its
 * origin. The target's origin must belong to some tenant to stop this being an open redirector, and
 * a rejected target still renders "signed out" rather than an error — the session really is gone,
 * and we don't confirm to a prober which URLs are registered.
 */
export async function handleLogout(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const target = url.searchParams.get("post_logout_redirect_uri");
	const tenant = target ? config.tenants.findPostLogoutTarget(target) : null;

	// Happens regardless of where (or whether) we can send the browser afterwards.
	const cleared = await endSession(request, env);

	if (!target || !tenant) {
		const res = errorPage({
			title: "Signed out",
			message: "You have been signed out.",
			status: 200,
			tenant,
		});
		res.headers.append("Set-Cookie", cleared);
		return res;
	}

	return redirect(target, { "Set-Cookie": cleared });
}
