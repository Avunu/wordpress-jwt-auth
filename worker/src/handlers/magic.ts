import type { WorkerConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
import { getFlowStub } from "../lib/flow";
import { hashSecret } from "../lib/otp";
import { readForm } from "../lib/http";
import { magicConfirmPage, errorPage } from "../ui";
import { alreadyUsed, completeSignIn } from "./authorize";

/**
 * GET /magic — render the confirm page ONLY. It never consumes the token, so an email security
 * scanner that auto-fetches the link does no harm. The human presses the button, which POSTs back
 * to actually sign in.
 */
export async function handleMagicGet(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const flow = url.searchParams.get("flow");
	const token = url.searchParams.get("token");
	if (!flow || !token) {
		return errorPage({ title: "Invalid link", message: "This sign-in link is incomplete." });
	}

	// Confirm the flow is still alive so we don't present a dead confirm page.
	const context = await getFlowStub(env, flow).getContext();
	if (!context) {
		return errorPage({
			title: "Link expired",
			message: "This sign-in link has expired. Return to the site and try again.",
			status: 410,
		});
	}

	return magicConfirmPage({ tenant: config.tenants.get(context.clientId), flow, token });
}

/**
 * POST /magic — the real human click. Consume the token and redirect back to WordPress.
 *
 * Deliberately cookie-independent so the link works in a different browser or on another device;
 * the 256-bit token is the whole authenticator. That also means the tenant has to come from the
 * flow record rather than from a cookie or the form.
 */
export async function handleMagicPost(
	request: Request,
	env: AuthWorkerEnv,
	config: WorkerConfig,
): Promise<Response> {
	const form = await readForm(request);
	const { flow } = form;
	const { token } = form;
	if (!flow || !token) {
		return errorPage({ title: "Invalid link", message: "This sign-in link is incomplete." });
	}

	const stub = getFlowStub(env, flow);
	const context = await stub.getContext();
	const tenant = context ? config.tenants.get(context.clientId) : null;
	if (!tenant) {
		return errorPage({
			title: "Link expired",
			message: "This sign-in link has expired. Return to the site and try again.",
			status: 410,
		});
	}

	const submittedHash = await hashSecret(token, flow);
	const result = await stub.verifyMagic(submittedHash);

	if (result.ok) {
		return completeSignIn(env, config.provider, tenant, result);
	}

	switch (result.reason) {
		case "already_used": {
			// Clicking the link a second time, or a mail client that pre-fetched and then the human
			// clicked. The sign-in already happened; say so instead of implying the link is broken.
			return alreadyUsed(tenant);
		}
		case "expired": {
			return errorPage({
				title: "Link expired",
				message: "This sign-in link has expired. Return to the site and try again.",
				status: 410,
				tenant,
			});
		}
		case "locked": {
			return errorPage({
				title: "Too many attempts",
				message: "Return to the site to start over.",
				status: 429,
				tenant,
			});
		}
		default: {
			return errorPage({
				title: "Invalid link",
				message: "This sign-in link is no longer valid. Return to the site and try again.",
				status: 400,
				tenant,
			});
		}
	}
}
