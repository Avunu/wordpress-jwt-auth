// @vitest-environment jsdom
import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import { CLIENT_SOURCE } from "../../src/client";
import { emailFormPage, pinFormPage, respond } from "../../src/ui";
import type { Screen } from "../../src/ui";
import type { Tenant } from "../../src/tenant";

// Exercising the client in a DOM, against the markup ui.ts really emits. The suite that shipped the
// [object HTMLInputElement] bug only ever asserted on the client's *source text*, so a defect in how
// it drives the DOM was invisible — these are the tests that close that gap.

const TENANT = {
	clientId: "alpha",
	displayName: "Alpha Site",
	redirectUris: ["https://alpha.test/?jwt_auth_callback=1"],
	sso: true,
} as Tenant;

/**
 * Swap a card in, exactly as the client does at runtime. The script itself is evaluated once for
 * the whole file, because that is how it actually lives: one delegated listener on `document`, with
 * cards replaced underneath it. Re-evaluating per test stacks duplicate listeners and every
 * assertion about "called once" quietly becomes a lie.
 */
async function mount(screen: Screen): Promise<HTMLFormElement> {
	const html = await respond(
		new Request("https://auth.test/authorize", { headers: { "X-Partial": "1" } }),
		screen,
	).text();
	document.body.innerHTML = html;
	return document.querySelector("form") as HTMLFormElement;
}

/**
 * Browsers expose a form's named controls _over_ the form's own properties (HTMLFormElement is
 * [LegacyOverrideBuiltIns]), so `<input name="action">` makes `form.action` the input. Neither
 * jsdom nor happy-dom implements this, so it is applied by hand — without it these tests cannot
 * fail the way production did.
 */
function shadowLikeABrowser(form: HTMLFormElement, name: string): void {
	const control = form.querySelector(`[name="${name}"]`);
	if (!control) {
		throw new Error(`no control named ${name} to shadow with`);
	}
	Object.defineProperty(form, name, { value: control, configurable: true });
}

function respondWith(init: { status?: number; body?: string; headers?: Record<string, string> }) {
	return vi.fn(
		async () =>
			new Response(init.body ?? '<div class="card" id="card">next</div>', {
				status: init.status ?? 200,
				headers: init.headers ?? {},
			}),
	);
}

beforeAll(() => {
	// eslint-disable-next-line no-eval -- running the real client is the entire point
	window.eval(CLIENT_SOURCE);
});

beforeEach(() => {
	document.body.innerHTML = "";
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("the enhanced client, in a DOM", () => {
	it("posts to the form's action URL even when a control shadows it", async () => {
		// The regression. With `<input name="action">` present and the client reading `form.action`,
		// fetch received an element, stringified it to "[object HTMLInputElement]", and the worker
		// answered 404 — which the client then swapped into the page as the text "Not found".
		const form = await mount(emailFormPage({ tenant: TENANT, siteKey: "k", flowId: "flow-abc" }));
		shadowLikeABrowser(form, "step");
		Object.defineProperty(form, "action", {
			value: form.querySelector('[name="step"]'),
			configurable: true,
		});

		const fetchMock = respondWith({});
		vi.stubGlobal("fetch", fetchMock);

		form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
		await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());

		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("/authorize");
		expect(String(url)).not.toContain("HTMLInputElement");
		expect(init.method).toBe("POST");
		expect((init.headers as Record<string, string>)["X-Partial"]).toBe("1");
	});

	it("sends the step and the typed values", async () => {
		const form = await mount(
			pinFormPage({ tenant: TENANT, email: "a@b.test", flowId: "flow-abc" }),
		);
		(form.querySelector("#pin") as HTMLInputElement).value = "123456";

		const fetchMock = respondWith({});
		vi.stubGlobal("fetch", fetchMock);
		form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
		await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());

		const body = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body as FormData;
		expect(body.get("step")).toBe("verify_code");
		expect(body.get("pin")).toBe("123456");
		// The flow the page was rendered for travels with the submission, so the worker can refuse
		// a click made on a page that a later render in another tab has since superseded.
		expect(body.get("flow")).toBe("flow-abc");
	});

	it("navigates on the redirect header instead of swapping", async () => {
		const form = await mount(
			pinFormPage({ tenant: TENANT, email: "a@b.test", flowId: "flow-abc" }),
		);
		const fetchMock = respondWith({
			headers: { "X-Auth-Redirect": "https://alpha.test/?code=abc&state=s" },
		});
		vi.stubGlobal("fetch", fetchMock);

		// jsdom refuses real navigation, so observe the assignment instead.
		const assigned: string[] = [];
		vi.stubGlobal("location", {
			get href(): string {
				return assigned.at(-1) ?? "";
			},
			set href(v: string) {
				assigned.push(v);
			},
		});

		form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
		await vi.waitFor(() => expect(assigned.length).toBe(1));

		expect(assigned[0]).toBe("https://alpha.test/?code=abc&state=s");
		// The card must be left alone — swapping a redirect body is how a 302 would have leaked the
		// WordPress page into our own layout.
		expect(document.querySelector("#card")?.textContent).toContain("Enter your code");
	});

	it("swaps the card on an error status rather than ignoring it", async () => {
		const form = await mount(
			pinFormPage({ tenant: TENANT, email: "a@b.test", flowId: "flow-abc" }),
		);
		vi.stubGlobal(
			"fetch",
			respondWith({
				status: 401,
				body: '<div class="card" id="card">That code is incorrect</div>',
			}),
		);

		form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
		await vi.waitFor(() =>
			expect(document.querySelector("#card")?.textContent).toContain("incorrect"),
		);
	});

	it("disables the submitter so a double-click cannot fire twice", async () => {
		const form = await mount(
			pinFormPage({ tenant: TENANT, email: "a@b.test", flowId: "flow-abc" }),
		);
		const button = form.querySelector("button") as HTMLButtonElement;
		let release: () => void = () => {};
		const gate = new Promise<void>((r) => {
			release = r;
		});
		const fetchMock = vi.fn(async () => {
			await gate;
			return new Response('<div class="card" id="card">ok</div>', { status: 200 });
		});
		vi.stubGlobal("fetch", fetchMock);

		// SubmitEvent carries the submitter; jsdom's Event does not, so supply it.
		const event = new Event("submit", { bubbles: true, cancelable: true });
		Object.defineProperty(event, "submitter", { value: button });
		form.dispatchEvent(event);

		await vi.waitFor(() => expect(button.disabled).toBe(true));
		release();
	});

	it("leaves a form without data-enhance to the browser", async () => {
		await mount(pinFormPage({ tenant: TENANT, email: "a@b.test", flowId: "flow-abc" }));
		document.body.insertAdjacentHTML("beforeend", '<form id="plain" action="/x"></form>');
		const plain = document.querySelector("#plain") as HTMLFormElement;

		const fetchMock = respondWith({});
		vi.stubGlobal("fetch", fetchMock);
		const event = new Event("submit", { bubbles: true, cancelable: true });
		plain.dispatchEvent(event);

		expect(fetchMock).not.toHaveBeenCalled();
		expect(event.defaultPrevented).toBe(false);
	});
});
