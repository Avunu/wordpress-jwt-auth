// Shared helpers for the wp-playground test harness: boot a WordPress instance with WooCommerce
// installed and the built plugin mounted, run PHP against it, and fetch pages as a logged-out
// visitor.
import { runCLI } from "@wp-playground/cli";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

export const HARNESS_DIR = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(HARNESS_DIR, "..", "..");
export const PLUGIN_PATH = "jwt-auth/jwt-auth.php";

// System Chrome (no Playwright browser download needed). Override with CHROME_PATH.
export const CHROME_PATH =
	process.env.CHROME_PATH ?? "/run/current-system/sw/bin/google-chrome-stable";

/** The marker class both injectors emit; counting it is what every test here is really doing. */
export const MARKER_CLASS = "jwt-auth-sso";

/**
 * Boot a playground server with WooCommerce installed, the built plugin mounted and activated, and
 * the JWT Auth constants defined by an mu-plugin.
 *
 * Note what is deliberately absent: the `login` step. Validator::blockDirectAuth() filters
 * `authenticate` at priority 1 and returns WP_Error for every username/password attempt, so
 * playground's auto-login cannot succeed once this plugin is active — and would fail in a way that
 * reads as a harness bug rather than the plugin working as designed. Every assertion here is about
 * the logged-out My Account page anyway, which is the only state that renders a login form.
 */
export async function bootPlayground({
	wp = process.env.WP_VERSION ?? "latest",
	port = 9410,
} = {}) {
	if (!existsSync(resolve(REPO_ROOT, "build/woo-login.js"))) {
		throw new Error("build/woo-login.js is missing — run `npm run build` in the repo root first.");
	}
	// The plugin's entrypoint requires vendor/autoload.php unconditionally, so a missing vendor/
	// is a PHP fatal on activation rather than an inactive plugin. Fail with the real cause.
	if (!existsSync(resolve(REPO_ROOT, "vendor/autoload.php"))) {
		throw new Error(
			"vendor/autoload.php is missing — run `composer install` in the repo root first.",
		);
	}
	return runCLI({
		command: "server",
		php: "8.4",
		wp,
		port,
		quiet: true,
		mount: [
			{ hostPath: REPO_ROOT, vfsPath: "/wordpress/wp-content/plugins/jwt-auth" },
			{
				hostPath: resolve(HARNESS_DIR, "mu-plugins"),
				vfsPath: "/wordpress/wp-content/mu-plugins",
			},
		],
		blueprint: {
			steps: [
				{
					step: "installPlugin",
					pluginData: { resource: "wordpress.org/plugins", slug: "woocommerce" },
					options: { activate: true },
				},
				{ step: "activatePlugin", pluginPath: PLUGIN_PATH },
			],
		},
	});
}

const MARK = "@@JWT@@";

/**
 * Run PHP against the booted WordPress (full bootstrap: wp-load fires plugins_loaded, so the
 * plugin's hooks are registered every call). The snippet is a function body with `$wpdb` in scope
 * that must `return` a JSON-encodable value; stray output is discarded and the value is emitted
 * between markers.
 */
export async function phpJson(server, snippet) {
	const code = `<?php
require '/wordpress/wp-load.php';
ob_start();
$__data = (function () {
	global $wpdb;
	${snippet}
})();
ob_end_clean();
echo ${JSON.stringify(MARK)} . wp_json_encode($__data) . ${JSON.stringify(MARK)};`;
	let res;
	try {
		res = await server.playground.run({ code });
	} catch (err) {
		// PHP fatals surface as a thrown PHPExecutionFailureError whose default stringification
		// dumps the entire response body as a byte-indexed object — unreadable in CI logs. Extract
		// just the "Fatal error: ..." line WordPress prints instead.
		const raw = String(err?.message ?? err);
		const fatal =
			/<b>Fatal error<\/b>:\s*(.*?)(?:<br|\s+in\s+<b>)/is.exec(raw) ??
			/Fatal error:\s*(.*)/i.exec(raw);
		throw new Error(
			fatal ? `PHP fatal error: ${fatal[1].trim()}` : `PHP execution failed: ${raw.slice(0, 300)}`,
		);
	}
	const text = res.text ?? "";
	const start = text.indexOf(MARK);
	const end = text.lastIndexOf(MARK);
	if (start === -1 || end === start) {
		throw new Error(`PHP produced no marked JSON. Raw output:\n${text}`);
	}
	const json = text.slice(start + MARK.length, end).trim();
	try {
		return JSON.parse(json);
	} catch {
		throw new Error(`PHP output was not valid JSON: ${json}`);
	}
}

/** How many times the SSO button marker appears in a chunk of HTML. */
export function countMarkers(html) {
	return html.split(`class="${MARKER_CLASS}"`).length - 1;
}

/** Fetch a path from the booted server as an anonymous visitor. */
export async function fetchPage(server, path) {
	const res = await fetch(new URL(path, server.serverUrl));
	if (!res.ok) {
		throw new Error(`GET ${path} → HTTP ${res.status}`);
	}
	return res.text();
}
