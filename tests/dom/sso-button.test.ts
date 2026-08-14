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
	exclusive: false,
};

/** The same site with JWT_AUTH_EXCLUSIVE on. */
const EXCLUSIVE: JwtAuthConfig = { ...CONFIG, exclusive: true };

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
		window.jwtAuth = { loginUrl: "", buttonLabel: "Sign in with SSO", exclusive: false };
		expect(readConfig(window)).toBeNull();
	});

	it("reads a well-formed config", () => {
		window.jwtAuth = { ...CONFIG };
		expect(readConfig(window)).toEqual(CONFIG);
	});

	it("carries the exclusive flag through", () => {
		window.jwtAuth = { ...EXCLUSIVE };
		expect(readConfig(window)?.exclusive).toBe(true);
	});

	it("treats a missing exclusive flag as off rather than failing the shape check", () => {
		// An older cached bundle paired with newer PHP, or the reverse. Absent must mean the additive
		// behaviour: that adds a button and never removes fields, so it is the safe reading. Rejecting
		// the config outright would disable the injector and leave a late-rendered form bare.
		(window as { jwtAuth?: unknown }).jwtAuth = {
			loginUrl: CONFIG.loginUrl,
			buttonLabel: CONFIG.buttonLabel,
		};

		expect(readConfig(window)).toEqual(CONFIG);
	});

	it("does not take a truthy non-boolean as consent to empty forms", () => {
		(window as { jwtAuth?: unknown }).jwtAuth = { ...CONFIG, exclusive: "no" };

		expect(readConfig(window)?.exclusive).toBe(false);
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
			exclusive: false,
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

describe("exclusive mode", () => {
	it("replaces the fields instead of standing above them", () => {
		// The whole point of JWT_AUTH_EXCLUSIVE, in the one place a server-side hook cannot reach: a
		// login form an AJAX theme or a modal rendered after the response. Prepending a button there
		// would put back exactly the choice between two doors that the switch removes.
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;
		const form = requireElement(".woocommerce-form-login");

		expect(injectInto(form, EXCLUSIVE)).toBe(true);

		expect(form.querySelector("input[type=password]")).toBeNull();
		expect(form.querySelector("input[name=username]")).toBeNull();
		expect(form.querySelector("button[name=login]")).toBeNull();
		expect(form.children).toHaveLength(1);
		expect(form.firstElementChild?.className).toBe(MARKER_CLASS);
	});

	it("empties the form rather than removing it, so the theme's layout survives", () => {
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;

		scan(document, EXCLUSIVE);

		expect(document.querySelector(".woocommerce-form-login")).not.toBeNull();
	});

	it("still leaves a server-replaced form alone", () => {
		// The marker guard is what keeps replaceChildren() from being destructive on a page the server
		// already handled — and in exclusive mode every WooCommerce form has been swapped server-side,
		// so this is the ordinary case rather than the edge one.
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM_WITH_SERVER_BUTTON;
		const before = requireElement(".woocommerce-form-login").innerHTML;

		expect(scan(document, EXCLUSIVE)).toBe(0);
		expect(requireElement(".woocommerce-form-login").innerHTML).toBe(before);
	});

	it("leaves the registration form alone, as ExclusiveLogin removes that server-side", () => {
		// `.woocommerce-form-register` is not a login form and never matches the selector. Registration
		// is closed by filtering WooCommerce's own hooks, not by emptying its markup in the browser —
		// a form emptied here would still have a live POST handler behind it.
		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;

		scan(document, EXCLUSIVE);

		const register = requireElement(".woocommerce-form-register");
		expect(register.querySelector("input[name=email]")).not.toBeNull();
	});

	it("catches a late-rendered form through the observer too", async () => {
		stops.push(install(window, EXCLUSIVE));

		document.body.innerHTML = MY_ACCOUNT_LOGIN_FORM;
		await waitForObserver();

		expect(buttons()).toHaveLength(1);
		expect(document.querySelector(".woocommerce-form-login input[type=password]")).toBeNull();
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
