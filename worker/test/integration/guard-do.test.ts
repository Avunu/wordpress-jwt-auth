import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import type { LoginGuard } from "../../src/guard-do";

// The guard's whole purpose is to survive what LoginFlow cannot: an attacker who exhausts a
// challenge's five attempts and simply opens another flow. Its counter therefore belongs to the
// address, and these tests drive it directly — the handler-level proof that a *new flow* still
// meets the same counter lives in handlers.test.ts.

const FREE_FAILURES = 10;

function guardFor(name: string): DurableObjectStub<LoginGuard> {
	const namespace = env.LOGIN_GUARD;
	if (!namespace) {
		throw new Error("LOGIN_GUARD binding missing from the test environment");
	}
	return namespace.get(namespace.idFromName(name));
}

/** Fail `n` times, returning the final verdict. */
async function failTimes(stub: DurableObjectStub<LoginGuard>, n: number) {
	let verdict = { locked: false, retryAfterMs: 0 };
	for (let i = 0; i < n; i++) {
		verdict = await stub.recordFailure();
	}
	return verdict;
}

async function isLocked(stub: DurableObjectStub<LoginGuard>): Promise<boolean> {
	const verdict = await stub.check();
	return verdict.locked;
}

async function retryAfterMs(stub: DurableObjectStub<LoginGuard>): Promise<number> {
	const verdict = await stub.check();
	return verdict.retryAfterMs;
}

describe("LoginGuard Durable Object", () => {
	it("tolerates ordinary mistyping, then locks on the failure that crosses the line", async () => {
		const stub = guardFor("guard-basic");

		// Ten is deliberately above LoginFlow's per-challenge cap of five: someone who fatfingers a
		// code twice over in one sitting must never meet this.
		const beforeLimit = await failTimes(stub, FREE_FAILURES);
		expect(beforeLimit.locked).toBe(false);
		expect(await isLocked(stub)).toBe(false);

		const crossing = await stub.recordFailure();
		expect(crossing.locked).toBe(true);
		// The verdict is returned by the attempt that causes the lockout, not the one after it —
		// otherwise the attacker gets one free guess past the limit.
		expect(crossing.retryAfterMs).toBeGreaterThan(0);
		expect(await isLocked(stub)).toBe(true);
	});

	it("does not extend a live lockout when an attacker keeps hammering", async () => {
		// Counting attempts made *during* a lockout would let anyone hold a victim's address shut
		// indefinitely, turning the defence into the denial of service it is meant to prevent.
		const stub = guardFor("guard-hammer");
		await failTimes(stub, FREE_FAILURES + 1);

		const first = await stub.check();
		expect(first.locked).toBe(true);

		const afterHammering = await failTimes(stub, 20);
		expect(afterHammering.locked).toBe(true);
		// Still the original lockout, counting down — never pushed further out.
		expect(afterHammering.retryAfterMs).toBeLessThanOrEqual(first.retryAfterMs);
	});

	it("escalates the backoff for each successive lockout in a run", async () => {
		const stub = guardFor("guard-escalate");
		await failTimes(stub, FREE_FAILURES + 1);
		const firstLockout = await retryAfterMs(stub);

		// Serve out the lockout, then fail once more. The free allowance is NOT refilled by a lockout
		// expiring — only by a genuinely quiet window — so this single failure locks again, longer.
		await runInDurableObject(stub, async (_instance, state) => {
			const record = await state.storage.get<{ lockedUntil: number }>("guard");
			expect(record).toBeDefined();
			await state.storage.put("guard", { ...record, lockedUntil: Date.now() - 1 });
		});
		expect(await isLocked(stub)).toBe(false);

		const second = await stub.recordFailure();
		expect(second.locked).toBe(true);
		expect(second.retryAfterMs).toBeGreaterThan(firstLockout);
	});

	it("forgets the run entirely on a successful sign-in", async () => {
		const stub = guardFor("guard-success");
		await failTimes(stub, FREE_FAILURES + 1);
		expect(await isLocked(stub)).toBe(true);

		await stub.recordSuccess();
		expect(await isLocked(stub)).toBe(false);

		// And the allowance is genuinely reset, not merely unlocked: proof of possession says the
		// earlier failures were this person fumbling their own code.
		const afterReset = await failTimes(stub, FREE_FAILURES);
		expect(afterReset.locked).toBe(false);
	});

	it("keeps each address independent", async () => {
		const victim = guardFor("guard-victim");
		const bystander = guardFor("guard-bystander");

		await failTimes(victim, FREE_FAILURES + 1);
		expect(await isLocked(victim)).toBe(true);
		expect(await isLocked(bystander)).toBe(false);
	});

	it("drops its storage on the retention alarm, so a quiet address costs nothing", async () => {
		const stub = guardFor("guard-alarm");
		await failTimes(stub, FREE_FAILURES + 1);

		await runInDurableObject(stub, async (instance, state) => {
			expect(await state.storage.get("guard")).toBeDefined();
			await instance.alarm();
			expect(await state.storage.get("guard")).toBeUndefined();
		});
		expect(await isLocked(stub)).toBe(false);
	});
});
