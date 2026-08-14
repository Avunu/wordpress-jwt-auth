// Test C — browser smoke (wp-playground + headless Chrome).
//
// The only test that reproduces the reported symptom. The duplicate "Sign in with SSO" button on
// /my-account existed exclusively in the post-script DOM: PHP emitted one, the browser script
// prepended a second, and every server-side assertion still counted one. Nothing short of running
// the real script against the real page could see it.
//
// It also covers the block checkout, where the old selector list put an SSO button inside the
// contact/address field group — again invisible to the server.
import { chromium } from "playwright-core";
import { bootPlayground, CHROME_PATH, MARKER_CLASS, phpJson } from "./lib.mjs";
import { tally } from "./assert.mjs";

const t = tally();
console.log(`Test C — browser smoke (WordPress ${process.env.WP_VERSION ?? "latest"})\n`);

let server;
let browser;
try {
	server = await bootPlayground({ port: 9430 });
	const url = server.serverUrl;
	browser = await chromium.launch({ executablePath: CHROME_PATH, headless: true });

	const page = await browser.newPage();
	const pageErrors = [];
	const consoleErrors = [];
	page.on("pageerror", (e) => pageErrors.push(`${e.name}: ${e.message}`));
	page.on("console", (m) => {
		if (m.type() === "error") consoleErrors.push(m.text());
	});

	const myAccountPath = new URL(await phpJson(server, `return wc_get_page_permalink('myaccount');`))
		.pathname;

	await page.goto(`${url}${myAccountPath}`, { waitUntil: "networkidle" });
	// The script is enqueued in the footer and installs a MutationObserver; give it a beat to run
	// so a second button would have appeared by the time we count.
	await page.waitForTimeout(1500);

	t.check("no uncaught page errors", pageErrors.length === 0, pageErrors.join(" | "));
	t.check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));

	const loginForms = await page.locator(".woocommerce-form-login").count();
	t.check("the classic login form rendered", loginForms === 1, `${loginForms} form(s)`);

	const buttons = await page.locator(`.${MARKER_CLASS}`).count();
	t.check(
		"exactly one SSO button after the script has run",
		buttons === 1,
		`found ${buttons} — this is the regression the fix is for`,
	);

	t.check(
		"the button is inside the login form",
		(await page.locator(`.woocommerce-form-login .${MARKER_CLASS}`).count()) === 1,
	);

	const href = await page.locator(`.${MARKER_CLASS} a`).first().getAttribute("href");
	t.check(
		"the button links to wp-login.php",
		(href ?? "").includes("wp-login.php"),
		`href=${href}`,
	);

	t.check(
		"the script received its config",
		await page.evaluate(() => typeof window.jwtAuth === "object"),
		"without this the script bails early and the count above would prove nothing",
	);

	// A late-rendered login form is the case the script exists for. Simulate what an AJAX or modal
	// login theme does, and confirm the observer picks it up — exactly once.
	await page.evaluate(() => {
		const form = document.createElement("form");
		form.className = "woocommerce-form woocommerce-form-login login";
		form.innerHTML = '<p class="form-row"><input type="text" name="username" /></p>';
		document.body.append(form);
	});
	await page.waitForTimeout(300);

	const afterLate = await page.locator(`.${MARKER_CLASS}`).count();
	t.check(
		"a login form rendered after load also gets exactly one button",
		afterLate === 2,
		`${afterLate} button(s) across 2 forms`,
	);

	// Block checkout: the old selector list matched `.wc-block-components-form`, which is the
	// checkout *fields* form, dropping an SSO button among the address inputs.
	//
	// The cart has to be non-empty first. An empty cart renders "your cart is currently empty" and
	// no fields form at all, which would let this check pass without ever meeting the markup it is
	// about — a green tick for a page that was never rendered.
	const productId = await phpJson(
		server,
		`$p = new WC_Product_Simple();
		$p->set_name('Playground Test Product');
		$p->set_regular_price('9.99');
		$p->set_catalog_visibility('visible');
		$p->set_status('publish');
		return $p->save();`,
	);
	await page.goto(`${url}/?add-to-cart=${productId}`, { waitUntil: "networkidle" });

	const checkoutPath = new URL(await phpJson(server, `return wc_get_checkout_url();`)).pathname;
	await page.goto(`${url}${checkoutPath}`, { waitUntil: "networkidle" });
	await page.waitForTimeout(2000);

	const fieldsForms = await page.locator(".wc-block-components-form").count();
	t.check(
		"the block checkout fields form rendered",
		fieldsForms > 0,
		`${fieldsForms} form(s) — without this the next check proves nothing`,
	);

	const checkoutButtons = await page.locator(`.wc-block-components-form .${MARKER_CLASS}`).count();
	t.check(
		"no SSO button inside the checkout fields form",
		checkoutButtons === 0,
		`${checkoutButtons} button(s) inside ${fieldsForms} fields form(s)`,
	);
} catch (err) {
	console.error(`\nUnexpected error: ${err.message}`);
	t.check("test completed without an unexpected error", false, err.message);
} finally {
	if (browser) await browser.close();
	if (server) await server[Symbol.asyncDispose]();
}

console.log(t.failures ? `\nTest C FAILED (${t.failures})` : "\nTest C PASSED");
process.exit(t.failures ? 1 : 0);
