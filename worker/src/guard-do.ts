import { DurableObject } from "cloudflare:workers";
import type { AuthWorkerEnv } from "./env";

// ---------------------------------------------------------------------------
// Per-identity brute-force guard: one instance per email address, addressed by
// a hash of it.
//
// LoginFlow already caps guesses at five — but per *challenge*, and setChallenge
// resets the counter. An attacker who exhausts five simply asks for another
// code, which costs one Turnstile solve, and starts again. The real ceiling on
// guessing a six-digit PIN was therefore the send throttle rather than any
// lockout, and a counter that resets whenever the attacker chooses is not a
// lockout at all.
//
// Counting failures against the identity instead of the attempt closes that: a
// new flow is a new challenge but the same person being attacked, so the budget
// follows the address across every flow, and the backoff grows the longer it is
// pushed. Checked before sending too, so a lockout also stops the mailbox being
// used as the delivery mechanism for the attack.
//
// The known cost, stated plainly: any per-identity lockout can be turned on its
// owner. Someone who enters a victim's address and fails on purpose can keep
// that address locked, which is a denial of service the per-flow counter did not
// have. It is accepted because the alternative is an unbounded guessing budget
// against a six-digit secret, and because the damage is bounded and self-healing
// — each round costs the attacker a Turnstile solve and a send under RL_EMAIL,
// lockouts top out at an hour, and everything is forgotten after a quiet window.
// A victim locked this way also still has any magic link already sent to them,
// which is deliberately not subject to the guard.
// ---------------------------------------------------------------------------

const KEY = "guard";

/**
 * Failures tolerated before the first lockout. Above LoginFlow's per-challenge cap of 5, so an
 * ordinary person mistyping a code twice over never meets it.
 */
const FREE_FAILURES = 10;

/** Consecutive failures are forgiven after this long without one. */
const WINDOW_MS = 3_600_000; // 1 hour

/** Lockout for the 1st, 2nd, 3rd… breach beyond FREE_FAILURES, in ms. Last value repeats. */
const BACKOFF_MS = [60_000, 300_000, 1_800_000, 3_600_000];

/** Storage is dropped this long after the last failure, so a quiet address costs nothing. */
const RETENTION_MS = 86_400_000; // 24 hours

interface StoredGuard {
	failures: number;
	/** When the run of failures began; a gap longer than WINDOW_MS starts a new run. */
	firstFailureAt: number;
	lastFailureAt: number;
	/** Lockouts imposed during this run — the index into BACKOFF_MS, so each one lasts longer. */
	lockouts: number;
	lockedUntil: number;
}

export interface GuardVerdict {
	locked: boolean;
	/** Milliseconds until another attempt is allowed. Zero when not locked. */
	retryAfterMs: number;
}

const OPEN: GuardVerdict = { locked: false, retryAfterMs: 0 };

/** A stored record read as a verdict: locked only while the lockout is still in the future. */
function verdictFor(record: StoredGuard, now: number): GuardVerdict {
	if (record.lockedUntil > now) {
		return { locked: true, retryAfterMs: record.lockedUntil - now };
	}
	return OPEN;
}

export class LoginGuard extends DurableObject<AuthWorkerEnv> {
	private async load(): Promise<StoredGuard | null> {
		return (await this.ctx.storage.get<StoredGuard>(KEY)) ?? null;
	}

	/** Is this identity currently locked out? Called before sending a code and before verifying. */
	async check(): Promise<GuardVerdict> {
		const r = await this.load();
		return r ? verdictFor(r, Date.now()) : OPEN;
	}

	/**
	 * A wrong PIN or magic token for this identity. Returns the verdict _after_ counting it, so the
	 * caller can lock out on the attempt that crosses the line rather than the one after.
	 */
	async recordFailure(): Promise<GuardVerdict> {
		return this.ctx.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const previous = await this.load();

			// Attempts made *during* a lockout are not counted. Otherwise an attacker who keeps
			// hammering a locked address drives the backoff up indefinitely, which is a denial of
			// service against the real owner rather than a defence of their account.
			if (previous && previous.lockedUntil > now) {
				return verdictFor(previous, now);
			}

			// A long enough quiet spell means the earlier run was somebody mistyping, not an attack.
			// Measured from the end of any lockout, not the last failure, so serving a lockout does not
			// itself age the run out and hand back a fresh budget of free guesses.
			const quietSince = previous ? Math.max(previous.lastFailureAt, previous.lockedUntil) : 0;
			const continuing = previous !== null && now - quietSince <= WINDOW_MS;

			const record: StoredGuard = {
				failures: continuing ? previous.failures + 1 : 1,
				firstFailureAt: continuing ? previous.firstFailureAt : now,
				lastFailureAt: now,
				lockouts: continuing ? previous.lockouts : 0,
				lockedUntil: 0,
			};

			// Past the free allowance every single failure locks again, each for longer than the last.
			// The allowance is not refilled when a lockout ends — only a quiet WINDOW_MS refills it.
			if (record.failures > FREE_FAILURES) {
				record.lockouts = Math.min(record.lockouts + 1, BACKOFF_MS.length);
				record.lockedUntil = now + (BACKOFF_MS[record.lockouts - 1] ?? 0);
			}

			await this.ctx.storage.put(KEY, record);
			await this.ctx.storage.setAlarm(now + RETENTION_MS);
			return verdictFor(record, now);
		});
	}

	/** Proof of possession. Clears the run outright — this was the real owner all along. */
	async recordSuccess(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}

	override async alarm(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}
}
