import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import type { UserSession } from "../../src/session-do";

// The SSO session's own semantics: what keeps a signed-in browser signed in, what quietly stops it,
// and what "sign out" actually destroys.

const EMAIL = "user@example.com";
const HOUR = 3_600_000;

function stubFor(sessionId: string): DurableObjectStub<UserSession> {
	const namespace = env.SSO_SESSION;
	if (!namespace) {
		throw new Error("SSO_SESSION binding missing from the test environment");
	}
	return namespace.get(namespace.idFromName(sessionId));
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => {
		setTimeout(resolve, ms);
	});
}

/** Read the persisted record and the scheduled expiry straight out of the instance. */
async function inspect(
	stub: DurableObjectStub<UserSession>,
): Promise<{ lastSeenAt: number; alarm: number }> {
	return runInDurableObject(stub, async (_instance, state) => {
		const record = await state.storage.get<{ lastSeenAt: number }>("session");
		const alarm = await state.storage.getAlarm();
		if (!record || alarm === null) {
			throw new Error("session or alarm missing");
		}
		return { lastSeenAt: record.lastSeenAt, alarm };
	});
}

describe("UserSession Durable Object", () => {
	it("starts linked to the site it was created on, and links others on demand", async () => {
		const stub = stubFor("sess-link");
		await stub.start(EMAIL, "alpha", HOUR, HOUR);

		const touched = await stub.touch();
		expect(touched).toEqual({ email: EMAIL, linkedTenants: ["alpha"] });

		const linked = await stub.link("beta");
		expect(linked?.linkedTenants).toEqual(["alpha", "beta"]);

		// Linking is idempotent — revisiting a site must not grow the list without bound.
		const relinked = await stub.link("beta");
		expect(relinked?.linkedTenants).toEqual(["alpha", "beta"]);
	});

	it("returns null for a session that was never started", async () => {
		expect(await stubFor("sess-missing").touch()).toBeNull();
		expect(await stubFor("sess-missing").link("alpha")).toBeNull();
	});

	it("lapses after the idle window, even though the absolute cap is far away", async () => {
		const stub = stubFor("sess-idle");
		await stub.start(EMAIL, "alpha", 50, HOUR);

		await sleep(120);
		expect(await stub.touch()).toBeNull();
	});

	it("rolls the idle window forward on every touch", async () => {
		// Asserted against the stored record and the scheduled alarm rather than by racing real
		// time: a version of this that slept just inside a short window and expected the session to
		// survive is only as reliable as the CI runner is fast, and a stalled runner fails it for
		// reasons that have nothing to do with the code.
		const stub = stubFor("sess-rolling");
		const idleMs = 60_000;
		await stub.start(EMAIL, "alpha", idleMs, HOUR);

		const before = await inspect(stub);
		await sleep(50);

		expect(await stub.touch()).not.toBeNull();
		const after = await inspect(stub);

		expect(after.lastSeenAt).toBeGreaterThan(before.lastSeenAt);
		// The alarm is the expiry: pushing it out is what "rolling" actually means. It tracks the
		// idle window here because that lands sooner than the absolute cap.
		expect(after.alarm).toBeGreaterThan(before.alarm);
		expect(after.alarm).toBe(after.lastSeenAt + idleMs);
	});

	it("dies at the absolute cap no matter how active it has been", async () => {
		// Touch continuously with an hour-long idle window: only the hard ceiling can end this, so
		// a slow runner makes the session die sooner rather than making the test flaky.
		const stub = stubFor("sess-absolute");
		await stub.start(EMAIL, "alpha", HOUR, 200);

		let died = false;
		for (let i = 0; i < 25 && !died; i++) {
			await sleep(40);
			died = (await stub.touch()) === null;
		}

		expect(died).toBe(true);
	});

	it("is gone for good after end()", async () => {
		const stub = stubFor("sess-end");
		await stub.start(EMAIL, "alpha", HOUR, HOUR);
		expect(await stub.touch()).not.toBeNull();

		await stub.end();
		expect(await stub.touch()).toBeNull();
	});
});
