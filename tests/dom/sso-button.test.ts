import { afterEach, describe, expect, it } from "vitest";
import {
	buildButton,
	injectInto,
	install,
	MARKER_CLASS,
	readConfig,
	scan,
} from "../../assets/src/sso-button";
import {
	BLOCK_CHECKOUT_FIELDS_FORM,
	CUSTOMER_ACCOUNT_BLOCK,
	MY_ACCOUNT_LOGIN_FORM,
	MY_ACCOUNT_LOGIN_FORM_WITH_SERVER_BUTTON,
} from "./fixtures";

const CONFIG: JwtAuthConfig = {
	loginUrl: "https://example.test/wp-login.php?redirect_to=my-account",
	buttonLabel: "Sign in with SSO",
};

const buttons = (): NodeListOf<Element> => document.querySelectorAll(`.${MARKER_CLASS}`);

/** Fail with the selector rather than a bare null-deref when a fixture stops matching. */
function requireElement(selector: string): Element {
	const el = document.querySelector(selector);
	if (!el) {
		throw new Error(`fixture is missing ${selector}`);
	}
	return el;
}

const stops: (() => void)[] = [];
afterEach(() => {
	for (const stop of stops.splice(0)) {
		stop();
	}
	document.body.innerHTML = "";
	delete window.jwtAuth;
});

describe("readConfig", () => {
	it("returns null when the inline script never ran", () => {
		expect(readConfig(window)).toBeNull();
	});

	it("returns null rather than throwing when the global is the wrong shape", () => {
		// A third-party script clobbering the name should make the button absent, not the page
		// broken.
		(window as { jwtAuth?: unknown }).jwtAuth = { loginUrl: 42 };
		expect(readConfig(window)).toBeNull();
	});

	it("returns null on an empty login URL, which would render a dead button", () => {
		window.jwtAuth = { loginUrl: "", buttonLabel: "Sign in with SSO" };
		expect(readConfig(window)).toBeNull();
	});

	it("reads a well-formed config", () => {
		window.jwtAuth = { ...CONFIG };
		expect(readConfig(window)).toEqual(CONFIG);
	});
});

describe("buildButton", () => {
	it("puts the label in as text, never as markup", () => {
		// buttonLabel comes from the JWT_AUTH_PROVIDER_NAME constant. It is not attacker input, but
		// it is interpolated into the page, and the previous implementation built the element with
		// an innerHTML template literal.
		const wrap = buildButton(document, {
			loginUrl: "https://example.test/wp-login.php",
			buttonLabel: '<img src=x onerror="alert(1)">',
		});

		expect(wrap.querySelector("img")).toBeNull();
		expect(wrap.textContent).toBe('<img src=x onerror="alert(1)">');
	});

	it("links to the configured login URL", () => {
		const wrap = buildButton(document, CONFIG);
		expect(wrap.querySelector("a")?.getAttribute("href")).toBe(CONFIG.loginUrl);
	});
});

describe("scan", () => {
	it("leaves a server-rendered button alone instead of adding a second", () => {
		// The regression this whole change exists for: PHP's woocommerce_login_form_start callback
		// already put a button in the form, and the script used to prepend its own above it.
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM_WITH_SERVER_BUTTON;

		expect(scan(document, CONFIG)).toBe(0);
		expect(buttons()).toHaveLength(1);
	});

	it("injects exactly one button into a login form that has none", () => {
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;

		expect(scan(document, CONFIG)).toBe(1);
		expect(buttons()).toHaveLength(1);
	});

	it("puts the button first, above the username field", () => {
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;
		scan(document, CONFIG);

		const form = document.querySelector(".woocommerce-form-login");
		expect(form?.firstElementChild?.className).toBe(MARKER_CLASS);
	});

	it("is idempotent across repeated scans", () => {
		// The MutationObserver re-scans on every subtree change, so scan() runs many times per page.
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;

		scan(document, CONFIG);
		scan(document, CONFIG);
		scan(document, CONFIG);

		expect(buttons()).toHaveLength(1);
	});

	it("ignores the registration form sharing the page", () => {
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;
		scan(document, CONFIG);

		expect(
			document.querySelector(".woocommerce-form-register")?.querySelector(`.${MARKER_CLASS}`),
		).toBeNull();
	});

	it("leaves the block checkout fields form untouched", () => {
		// `.wc-block-components-form` is contact/address fields, not a login form. Matching it put an
		// SSO button in the middle of the checkout address block.
		document.body.innerHTML = BLOCK_CHECKOUT_FIELDS_FORM;

		expect(scan(document, CONFIG)).toBe(0);
		expect(buttons()).toHaveLength(0);
	});

	it("leaves the customer account block untouched", () => {
		document.body.innerHTML = CUSTOMER_ACCOUNT_BLOCK;

		expect(scan(document, CONFIG)).toBe(0);
		expect(buttons()).toHaveLength(0);
	});
});

describe("injectInto", () => {
	it("reports whether it did anything", () => {
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;
		const form = requireElement(".woocommerce-form-login");

		expect(injectInto(form, CONFIG)).toBe(true);
		expect(injectInto(form, CONFIG)).toBe(false);
	});
});

describe("install", () => {
	it("catches a login form rendered after page load", async () => {
		// The reason the script exists at all: an AJAX-rendering theme or a login modal puts the
		// form in the document after the response the PHP hook could decorate.
		stops.push(install(window, CONFIG));
		expect(buttons()).toHaveLength(0);

		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;
		await waitForObserver();

		expect(buttons()).toHaveLength(1);
	});

	it("does not add a second button when a late form arrives already decorated", async () => {
		stops.push(install(window, CONFIG));

		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM_WITH_SERVER_BUTTON;
		await waitForObserver();

		expect(buttons()).toHaveLength(1);
	});

	it("stops observing once stopped", async () => {
		const stop = install(window, CONFIG);
		stop();

		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;
		await waitForObserver();

		expect(buttons()).toHaveLength(0);
	});
});

/** MutationObserver callbacks are microtask-scheduled; yield until they have drained. */
function waitForObserver(): Promise<void> {
	return new Promise((resolve) => {
		setTimeout(resolve, 0);
	});
}
