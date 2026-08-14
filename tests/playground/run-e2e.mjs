// Test B — real WordPress + real WooCommerce, no browser.
//
// Asserts the server side of the contract: the classic My Account login form comes back with
// exactly one SSO button in the markup, the script and its config are enqueued, and the enqueued
// version matches the build manifest.
//
// This test cannot see the reported bug. The second button was added by the script, so the HTML
// that leaves PHP has always had exactly one — run-browser.mjs is what catches the duplicate. What
// this one guards is everything that has to be true before the script is even reached.
import { bootPlayground, countMarkers, fetchPage, MARKER_CLASS, phpJson } from "./lib.mjs";
import { tally } from "./assert.mjs";

const t = tally();

console.log("Test B — server-rendered My Account (WordPress + WooCommerce)");

const server = await bootPlayground();
try {
	const active = await phpJson(
		server,
		`return ['woo' => class_exists('WooCommerce'), 'jwt' => class_exists('JwtAuth\\\\WooCommerce')];`,
	);
	t.check("WooCommerce is active", active.woo);
	t.check("the plugin autoloaded", active.jwt);

	const mode = await phpJson(server, `return JwtAuth\\Config::detectMode()->name;`);
	t.check("plugin is in OIDC mode", mode === "Oidc", `mode=${mode}`);

	const myAccountUrl = await phpJson(server, `return wc_get_page_permalink('myaccount');`);
	t.check("My Account page exists", typeof myAccountUrl === "string" && myAccountUrl.length > 0);

	const html = await fetchPage(server, new URL(myAccountUrl).pathname);

	t.check(
		"the login form rendered",
		html.includes("woocommerce-form-login"),
		"logged-out My Account shows the classic form",
	);

	const markers = countMarkers(html);
	t.check(
		"exactly one server-rendered SSO button",
		markers === 1,
		`found ${markers} .${MARKER_CLASS} in the response`,
	);

	t.check("button label came through", html.includes("Sign in with SSO"));
	t.check(
		"button routes through wp-login.php",
		/class="jwt-auth-sso"><a href="[^"]*wp-login\.php/.test(html),
		"the login redirect is what starts the OIDC flow",
	);

	t.check(
		"fallback script is enqueued",
		html.includes("build/woo-login.js"),
		"needed for AJAX/modal login forms",
	);
	t.check(
		"script config is inlined before it",
		html.includes("window.jwtAuth ="),
		"wp_add_inline_script(…, 'before')",
	);

	const manifestVersion = await phpJson(
		server,
		`$a = require WP_PLUGIN_DIR . '/jwt-auth/build/woo-login.asset.php'; return $a['version'];`,
	);
	t.check(
		"enqueued version matches the build manifest",
		html.includes(`woo-login.js?ver=${manifestVersion}`),
		`manifest version=${manifestVersion}`,
	);

	// The register form shares the page when registration is enabled; it must stay untouched.
	const registerIdx = html.indexOf("woocommerce-form-register");
	t.check(
		"no button in the registration column",
		registerIdx === -1 || countMarkers(html.slice(registerIdx)) === 0,
		"woocommerce_register_form_* is a separate hook family",
	);
} finally {
	await server[Symbol.asyncDispose]();
}

console.log(t.failures ? `\n${t.failures} failure(s)\n` : "\nAll checks passed\n");
process.exit(t.failures ? 1 : 0);
