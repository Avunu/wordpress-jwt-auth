import { env } from "cloudflare:workers";
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

	it("keeps a busy session alive by rolling the idle window forward", async () => {
		const stub = stubFor("sess-rolling");
		await stub.start(EMAIL, "alpha", 150, HOUR);

		// Three gaps that each individually fit inside the window, totalling more than one window.
		for (let i = 0; i < 3; i++) {
			await sleep(80);
			expect(await stub.touch()).not.toBeNull();
		}
	});

	it("dies at the absolute cap no matter how active it has been", async () => {
		const stub = stubFor("sess-absolute");
		await stub.start(EMAIL, "alpha", HOUR, 100);

		await sleep(40);
		expect(await stub.touch()).not.toBeNull(); // Still inside the cap.
		await sleep(120);
		expect(await stub.touch()).toBeNull();
	});

	it("is gone for good after end()", async () => {
		const stub = stubFor("sess-end");
		await stub.start(EMAIL, "alpha", HOUR, HOUR);
		expect(await stub.touch()).not.toBeNull();

		await stub.end();
		expect(await stub.touch()).toBeNull();
	});
});
