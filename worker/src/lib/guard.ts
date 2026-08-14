import type { AuthWorkerEnv } from "../env";
import type { GuardVerdict, LoginGuard } from "../guard-do";

/**
 * The guard is addressed by a hash of the address, never the address itself: a Durable Object id is
 * derived from its name and shows up in logs and dashboards, and "which addresses have accounts
 * here" is not something this system should leak through its own telemetry.
 *
 * Taking the hash rather than the address also lets the verify path count a failure without ever
 * holding the address it belongs to — LoginFlow hands back only the hash when a guess is wrong.
 */
function guardFor(env: AuthWorkerEnv, emailHash: string): DurableObjectStub<LoginGuard> | null {
	const namespace = env.LOGIN_GUARD;
	if (!namespace) {
		return null;
	}
	return namespace.get(namespace.idFromName(emailHash));
}

const OPEN: GuardVerdict = { locked: false, retryAfterMs: 0 };

/**
 * Deployments without the binding keep their previous behaviour rather than failing shut, so a
 * single-site wrapper can adopt a new core version without a Durable Object migration. That is a
 * real trade — an absent binding silently means no cross-flow lockout — so the fleet's own
 * wranglers all declare it, and only third-party wrappers can end up without one.
 */
export async function guardCheck(env: AuthWorkerEnv, emailHash: string): Promise<GuardVerdict> {
	return (await guardFor(env, emailHash)?.check()) ?? OPEN;
}

export async function guardFailure(env: AuthWorkerEnv, emailHash: string): Promise<GuardVerdict> {
	return (await guardFor(env, emailHash)?.recordFailure()) ?? OPEN;
}

export async function guardSuccess(env: AuthWorkerEnv, emailHash: string): Promise<void> {
	await guardFor(env, emailHash)?.recordSuccess();
}

/** Whole minutes, rounded up — what the lockout message quotes. */
export function retryMinutes(verdict: GuardVerdict): number {
	return Math.max(1, Math.ceil(verdict.retryAfterMs / 60_000));
}
