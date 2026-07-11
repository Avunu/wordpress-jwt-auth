import type { AppConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
import { getFlowStub } from "../lib/flow";
import { hashSecret } from "../lib/otp";
import { readForm } from "../lib/http";
import { magicConfirmPage, errorPage } from "../ui";
import { finishRedirect } from "./authorize";

/**
 * GET /magic — render the confirm page ONLY. It never consumes the token, so an email security
 * scanner that auto-fetches the link does no harm. The human presses the button, which POSTs back
 * to actually sign in.
 */
export async function handleMagicGet(
	request: Request,
	env: AuthWorkerEnv,
	config: AppConfig,
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

	return magicConfirmPage({ siteLabel: config.issuerHost, flow, token });
}

/** POST /magic — the real human click. Consume the token and redirect back to WordPress. */
export async function handleMagicPost(request: Request, env: AuthWorkerEnv): Promise<Response> {
	const form = await readForm(request);
	const { flow } = form;
	const { token } = form;
	if (!flow || !token) {
		return errorPage({ title: "Invalid link", message: "This sign-in link is incomplete." });
	}

	const submittedHash = await hashSecret(token, flow);
	const result = await getFlowStub(env, flow).verifyMagic(submittedHash);

	if (result.ok) {
		return finishRedirect(result.redirectUri, result.code, result.state);
	}

	switch (result.reason) {
		case "expired": {
			return errorPage({
				title: "Link expired",
				message: "This sign-in link has expired. Return to the site and try again.",
				status: 410,
			});
		}
		case "locked": {
			return errorPage({
				title: "Too many attempts",
				message: "Return to the site to start over.",
				status: 429,
			});
		}
		default: {
			return errorPage({
				title: "Invalid link",
				message: "This sign-in link is no longer valid. Return to the site and try again.",
				status: 400,
			});
		}
	}
}
