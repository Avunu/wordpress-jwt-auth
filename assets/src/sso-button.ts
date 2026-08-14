// The SSO button injector, as pure functions over a document.
//
// This is a *fallback*, and understanding that is the whole design. WooCommerce renders its login
// form server-side from `templates/myaccount/form-login.php` and `templates/global/form-login.php`,
// both of which fire `woocommerce_login_form_start` — so on an ordinary My Account or Checkout page
// the button is already in the markup before this script parses, and `scan()` correctly does
// nothing. What is left for the browser is the case the server cannot reach: a login form that
// appears *after* the response, from an AJAX-rendering theme, a modal login, or a future blockified
// My Account.
//
// The guard is the rendered marker, not a private flag. An earlier version tracked its own work
// with `form.dataset.jwtAuthDone`, which answers "did I already inject here?" — a question that
// silently omits the server. It shipped a second button under every server-rendered one on
// /my-account. Asking the document what it already contains covers both injectors at once, and
// there is no state to keep in sync.

/** Class on the wrapper div. Both this script and WooCommerce::renderSsoButton() emit it. */
export const MARKER_CLASS = "jwt-auth-sso";

/**
 * Login forms only.
 *
 * WooCommerce puts this class on the classic login form in both templates that render one. It is
 * deliberately the only selector: `.wc-block-components-form` is the block checkout's _fields_ form
 * (contact and address groups, not a login), and `.wp-block-woocommerce-customer-account form`
 * never matches, because that block renders links and buttons but no form at all. Both were in an
 * earlier selector list; the first put an SSO button in the middle of the checkout address fields.
 */
export const LOGIN_FORM_SELECTOR = ".woocommerce-form-login";

/**
 * The real `window`. Constructors like MutationObserver are declared on globalThis rather than on
 * the Window interface, so a bare `Window` cannot see them — passing the window in (instead of
 * reaching for the global) is what lets a test drive this against a jsdom document.
 */
export type BrowserWindow = Window & typeof globalThis;

/** Read the server-provided config, or null when it is absent or not the shape we need. */
export function readConfig(view: Window): JwtAuthConfig | null {
	const raw = view.jwtAuth;
	if (!raw || typeof raw.loginUrl !== "string" || typeof raw.buttonLabel !== "string") {
		return null;
	}
	if (raw.loginUrl === "") {
		return null;
	}
	return { loginUrl: raw.loginUrl, buttonLabel: raw.buttonLabel };
}

/** Build the button. Nodes and textContent, never innerHTML — the label is a site-owner string. */
export function buildButton(doc: Document, config: JwtAuthConfig): HTMLDivElement {
	const wrap = doc.createElement("div");
	wrap.className = MARKER_CLASS;

	const link = doc.createElement("a");
	link.href = config.loginUrl;
	link.className = "woocommerce-button button";
	link.textContent = config.buttonLabel;

	wrap.append(link);
	return wrap;
}

/**
 * Add a button to one form, unless it already has one.
 *
 * Returns whether it injected, which is what makes "did the server already do this?" assertable in
 * a test rather than something you infer by counting nodes afterwards.
 */
export function injectInto(form: Element, config: JwtAuthConfig): boolean {
	if (form.querySelector(`.${MARKER_CLASS}`)) {
		return false;
	}
	form.prepend(buildButton(form.ownerDocument, config));
	return true;
}

/** Add a button to every login form under `root` that does not already have one. */
export function scan(root: ParentNode, config: JwtAuthConfig): number {
	let injected = 0;
	for (const form of root.querySelectorAll(LOGIN_FORM_SELECTOR)) {
		if (injectInto(form, config)) {
			injected += 1;
		}
	}
	return injected;
}

/** How long to keep watching for a late-rendered login form. */
export const OBSERVE_MS = 8000;

/**
 * Scan now, then watch for forms rendered later. Returns a stop function.
 *
 * The observer disconnects itself after OBSERVE_MS because it exists for render timing, not for the
 * lifetime of the page: a form that first appears minutes in is a modal the user opened, and by
 * then the scan on its own mutation has already run. Holding a subtree observer on `body` forever
 * to catch nothing is a cost paid on every My Account page view.
 */
export function install(view: BrowserWindow, config: JwtAuthConfig): () => void {
	const doc = view.document;
	scan(doc, config);

	const observer = new view.MutationObserver(() => {
		scan(doc, config);
	});
	observer.observe(doc.body, { childList: true, subtree: true });

	const timer = view.setTimeout(() => {
		observer.disconnect();
	}, OBSERVE_MS);

	return () => {
		observer.disconnect();
		view.clearTimeout(timer);
	};
}
