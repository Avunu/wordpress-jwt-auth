import { describe, it, expect } from "vitest";
import { CLIENT_SOURCE, CLIENT_SOURCE_HASH } from "../../src/client";

/**
 * The CSP header is built synchronously and crypto.subtle is not, so the script's hash is a
 * hardcoded constant. This is the only thing standing between an edit to the script and a page
 * whose own client is silently refused by the browser — a failure that would look exactly like the
 * form-action incident: fine in curl, broken in a browser.
 */
describe("client script integrity", () => {
	it("the published hash matches the script it claims to describe", async () => {
		const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(CLIENT_SOURCE));
		const bytes = Array.from(new Uint8Array(digest), (b) => String.fromCodePoint(b)).join("");
		const actual = `sha256-${btoa(bytes)}`;

		expect(actual).toBe(CLIENT_SOURCE_HASH);
	});

	it("stays small enough to inline", async () => {
		// The reason we hand-rolled this rather than taking htmx, whose 36 KB is ~11x the entire page.
		expect(CLIENT_SOURCE.length).toBeLessThan(2048);
	});

	it("never needs eval, so the CSP can stay strict", () => {
		expect(CLIENT_SOURCE).not.toContain("eval(");
		expect(CLIENT_SOURCE).not.toContain("new Function");
	});

	it("cannot break out of the script element it is inlined into", () => {
		// It is our own constant, not user input, but the failure mode if that ever stopped being
		// true is arbitrary markup injection on the auth page.
		expect(CLIENT_SOURCE.toLowerCase()).not.toContain("</script");
	});

	it("falls back to a native submit rather than trapping the user", () => {
		// If fetch throws — offline, blocked, DNS — the browser must still be able to post the form.
		expect(CLIENT_SOURCE).toContain("form.submit()");
	});
});
