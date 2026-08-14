// Test E — JWT_AUTH_EXCLUSIVE against real WordPress, real WooCommerce and a real HTML parser.
//
// Everything this switch does is a claim about somebody else's code, which is why it needs a real
// install rather than a fake. Three claims in particular cannot be checked any other way:
//
//   1. `<template>`. wp_login_form() offers no hook that can suppress its username and password
//      fields, so the plugin closes the form early and wraps them in a <template> instead. That is
//      only true if an HTML5 parser agrees: template contents belong to a separate document
//      fragment, so `document.querySelector('input[name=pwd]')` must come back null. A string
//      assertion can show the tags are in the right order and nothing more — and the stray </form>
//      core appends afterwards is precisely the sort of thing PHP cannot tell you is harmless.
//
//   2. remove_action() addresses. The plugin unhooks WC_Form_Handler's registration and
//      password-reset handlers by naming a hook, a [class, method] pair and a priority. Get any of
//      the three wrong — because WooCommerce moved it — and WordPress returns false and says
//      nothing. The pair of checks below is self-validating: process_login must still be found at
//      wp_loaded/20 through the same convention, so a `false` for the others means removed rather
//      than misaddressed.
//
//   3. That WooCommerce actually renders this plugin's templates in place of its own.
//
// It also pins the things that must keep working: wp-login.php still verifies post passwords and
// still logs people out, because blocking that screen wholesale is how a lockdown becomes a lockout.
import { chromium } from "playwright-core";
import {
	bootPlayground,
	CHROME_PATH,
	countMarkers,
	fetchPage,
	MARKER_CLASS,
	phpJson,
} from "./lib.mjs";
import { tally } from "./assert.mjs";

const t = tally();
console.log(`Test E — JWT_AUTH_EXCLUSIVE (WordPress ${process.env.WP_VERSION ?? "latest"})\n`);

/** Any credential input, however the template spells its name. */
const CREDENTIAL_INPUT =
	'input[type="password"], input[name="username"], input[name="log"], input[name="pwd"]';

let server;
let browser;
try {
	server = await bootPlayground({ port: 9440, muPlugins: "mu-plugins-exclusive" });
	browser = await chromium.launch({ executablePath: CHROME_PATH, headless: true });
	const page = await browser.newPage();

	// -------------------------------------------------------------------
	// The switch is on
	// -------------------------------------------------------------------

	const env = await phpJson(
		server,
		`return [
			'exclusive' => JwtAuth\\Config::exclusive(),
			'mode'      => JwtAuth\\Config::detectMode()->name,
			'woo'       => class_exists('WooCommerce'),
		];`,
	);
	t.check("JWT_AUTH_EXCLUSIVE is on", env.exclusive === true);
	t.check("plugin is in OIDC mode", env.mode === "Oidc", `mode=${env.mode}`);
	t.check("WooCommerce is active", env.woo);

	// -------------------------------------------------------------------
	// WooCommerce My Account — the surface the whole feature is about
	// -------------------------------------------------------------------

	const myAccountPath = new URL(await phpJson(server, `return wc_get_page_permalink('myaccount');`))
		.pathname;
	const myAccount = await fetchPage(server, myAccountPath);

	t.check(
		"exactly one SSO button on logged-out My Account",
		countMarkers(myAccount) === 1,
		`found ${countMarkers(myAccount)} .${MARKER_CLASS}`,
	);
	t.check(
		"WooCommerce's own login form is gone, not decorated",
		!myAccount.includes('name="password"') && !myAccount.includes('id="username"'),
		"ExclusiveLogin::wooTemplate() substitutes myaccount/form-login.php",
	);
	t.check(
		"and so is the registration column beside it",
		!myAccount.includes("woocommerce-form-register"),
		"the register form asks for a password nothing could ever accept",
	);

	// Every template in the substitution list, resolved through real WooCommerce. The My Account page
	// above exercises one of the six; the rest belong to the classic checkout, the pay and
	// order-received pages, the reset flow and /wc-auth/v1 — none of which this suite renders, and all
	// of which would fall back silently to WooCommerce's password form if a path were wrong, since
	// wooTemplate() prefers WooCommerce's own template over a file it cannot find.
	const substitutions = await phpJson(
		server,
		`$out = [];
		foreach ([
			'myaccount/form-login.php',
			'myaccount/form-lost-password.php',
			'myaccount/form-reset-password.php',
			'global/form-login.php',
			'checkout/form-login.php',
			'auth/form-login.php',
		] as $name) {
			$original = WC()->plugin_path() . '/templates/' . $name;
			$located   = apply_filters('wc_get_template', $original, $name, [], '', '');
			$out[$name] = $located !== $original
				&& is_file($located)
				&& str_contains($located, 'plugins/jwt-auth/templates/woocommerce/');
		}
		return $out;`,
	);
	for (const [name, ok] of Object.entries(substitutions)) {
		t.check(`${name} resolves to a template this plugin ships`, ok === true);
	}

	// Registration is closed by unhooking the handler, not only by dropping the markup — a form
	// removed from the page with a live POST handler behind it is not a closed door.
	const wooHooks = await phpJson(
		server,
		`return [
			'login'         => has_action('wp_loaded', ['WC_Form_Handler', 'process_login']),
			'registration'  => has_action('wp_loaded', ['WC_Form_Handler', 'process_registration']),
			'lost_password' => has_action('wp_loaded', ['WC_Form_Handler', 'process_lost_password']),
			'reset'         => has_action('wp_loaded', ['WC_Form_Handler', 'process_reset_password']),
			'reset_link'    => has_action('template_redirect', ['WC_Form_Handler', 'redirect_reset_password_link']),
		];`,
	);
	t.check(
		"the hook address convention finds real WooCommerce handlers",
		wooHooks.login === 20,
		`process_login@${JSON.stringify(wooHooks.login)} — without this the removals below prove nothing`,
	);
	for (const [name, key] of [
		["registration", "registration"],
		["lost password", "lost_password"],
		["password reset", "reset"],
		["the reset-link redirect", "reset_link"],
	]) {
		t.check(
			`WooCommerce's ${name} handler is unhooked`,
			wooHooks[key] === false,
			`has_action returned ${JSON.stringify(wooHooks[key])}`,
		);
	}

	// The reason the reset handler matters more than the form: it ends in
	// wc_set_customer_auth_cookie(), so completing WooCommerce's reset flow granted a session with
	// the provider never consulted. Refusing the key stops it before a link can even be sent.
	const resetKey = await phpJson(
		server,
		`$id = wp_create_user('resetme', 'irrelevant-password', 'resetme@example.test');
		if (is_wp_error($id)) { return ['error' => $id->get_error_message()]; }
		$key = get_password_reset_key(new WP_User($id));
		return [
			'refused' => is_wp_error($key),
			'code'    => is_wp_error($key) ? $key->get_error_code() : null,
			'allowed' => (bool) apply_filters('allow_password_reset', true, $id),
		];`,
	);
	t.check(
		"no password reset key can be issued",
		resetKey.refused === true,
		`code=${resetKey.code}`,
	);
	t.check("because allow_password_reset is false", resetKey.allowed === false);

	const lostPassword = await fetchPage(server, `${myAccountPath}lost-password/`);
	t.check(
		"the lost-password page offers no form",
		!lostPassword.includes('name="user_login"'),
		"WooCommerce points lostpassword_url here, so old links still land",
	);
	t.check("and points at the provider instead", countMarkers(lostPassword) >= 1);

	// Account creation that mints a password: the checkout checkbox and the order-confirmation block.
	const accountCreation = await phpJson(
		server,
		`return [
			'checkout' => (bool) WC()->checkout()->is_registration_enabled(),
			'delayed'  => get_option('woocommerce_enable_delayed_account_creation', 'yes'),
		];`,
	);
	t.check("checkout account creation is off", accountCreation.checkout === false);
	t.check(
		"order-confirmation account creation is off",
		accountCreation.delayed === "no",
		`option reads ${JSON.stringify(accountCreation.delayed)}`,
	);

	// -------------------------------------------------------------------
	// Core: wp_login_form(), judged by a browser
	// -------------------------------------------------------------------

	const coreForm = await phpJson(server, `return wp_login_form(['echo' => false]);`);
	t.check(
		"wp_login_form() still returns markup",
		typeof coreForm === "string" && coreForm.includes("<form"),
		"a bare empty string would pass the next checks for the wrong reason",
	);

	await page.setContent(`<!doctype html><html><body>${coreForm}</body></html>`);

	t.check(
		"the SSO button is in the document",
		(await page.locator(`.${MARKER_CLASS}`).count()) === 1,
	);
	t.check("the button is visible", await page.locator(`.${MARKER_CLASS} a`).first().isVisible());
	t.check(
		"no credential field is in the document tree at all",
		(await page.locator(CREDENTIAL_INPUT).count()) === 0,
		"template contents parse into a separate fragment — this is the claim PHP cannot make",
	);
	t.check(
		"the fields are inside the template, not deleted",
		await page.evaluate(() => {
			const tpl = document.querySelector("template.jwt-auth-suppressed-login");
			return Boolean(
				tpl instanceof HTMLTemplateElement && tpl.content.querySelector("input[name=pwd]"),
			);
		}),
		"proves the previous check is about inertness rather than a missing fixture",
	);
	t.check(
		"the rendered form has nothing left to submit",
		await page.evaluate(() => {
			const form = document.querySelector("form");
			return Boolean(form instanceof HTMLFormElement && form.elements.length === 0);
		}),
		"form.elements excludes template contents, which is the same rule the submission algorithm uses",
	);

	// -------------------------------------------------------------------
	// Core: the Login/out block
	// -------------------------------------------------------------------

	const loginBlock = await phpJson(
		server,
		`return do_blocks('<!-- wp:loginout {"displayLoginAsForm":true} /-->');`,
	);
	await page.setContent(`<!doctype html><html><body>${loginBlock}</body></html>`);

	t.check(
		'the "display login as form" block renders no credential field',
		(await page.locator(CREDENTIAL_INPUT).count()) === 0,
		"render_block_data clears the attribute before render_block_core_loginout() sees it",
	);
	t.check(
		"it renders a link to wp-login.php instead",
		(await page.locator('a[href*="wp-login.php"]').count()) >= 1,
		"which is where the provider redirect lives",
	);

	// -------------------------------------------------------------------
	// wp-login.php: refused as a sign-in screen, intact as everything else
	// -------------------------------------------------------------------
	//
	// This suite's issuer is deliberately unroutable, so OIDC discovery fails on every request and
	// OidcClient::redirectToProvider() falls through — which is exactly the path that used to leave a
	// password box on the screen.

	const loginScreen = await fetch(new URL("/wp-login.php", server.serverUrl), {
		redirect: "manual",
	});
	const loginScreenBody = await loginScreen.text();
	t.check(
		"an unreachable provider yields a notice, not a password form",
		!/name="pwd"/.test(loginScreenBody),
		`HTTP ${loginScreen.status}`,
	);
	t.check(
		"and says why",
		/temporarily unavailable/i.test(loginScreenBody),
		loginScreenBody.slice(0, 120).replaceAll("\n", " "),
	);
	t.check(
		"with a 503 rather than a 200",
		loginScreen.status === 503,
		`HTTP ${loginScreen.status} — a soft failure the IdP can recover from`,
	);

	// wp-login.php is also how a visitor unlocks a password-protected post, confirms a privacy
	// request, and signs out. The claim here is that core's own handler ran, not that the response was
	// a success — a bare GET of `confirmaction` is a 500 from core's own "Missing request ID", and
	// `logout` without a nonce is core's 403 confirmation page. So each expects a fingerprint of
	// core's handling alongside the absence of this plugin's notice; a status check alone would either
	// fail on core's behaviour or pass on ours.
	for (const [action, coreEvidence] of [
		["logout", /attempting to log out/i],
		["postpass", null],
		["confirmaction", /Missing request ID/i],
	]) {
		const res = await fetch(new URL(`/wp-login.php?action=${action}`, server.serverUrl), {
			redirect: "manual",
		});
		const body = await res.text();
		t.check(
			`wp-login.php?action=${action} reaches core rather than the block`,
			!/temporarily unavailable/i.test(body) && (coreEvidence === null || coreEvidence.test(body)),
			`HTTP ${res.status} — blocking this turns a lockdown into a lockout`,
		);
	}
} catch (err) {
	console.error(`\nUnexpected error: ${err.stack ?? err.message}`);
	t.check("test completed without an unexpected error", false, err.message);
} finally {
	if (browser) await browser.close();
	if (server) await server[Symbol.asyncDispose]();
}

console.log(t.failures ? `\nTest E FAILED (${t.failures})` : "\nTest E PASSED");
process.exit(t.failures ? 1 : 0);
