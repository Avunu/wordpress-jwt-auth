// Test A — the build output, with no WordPress involved.
//
// Guards the seam between rolldown and PHP: WooCommerce::enqueueAssets() `require`s the manifest
// and reads two keys off it. If the emitted shape drifts, the plugin fatals on every My Account
// page view, and no amount of DOM testing would notice — the bundle itself is fine.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { tally } from "./assert.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const t = tally();

console.log("Test A — build output");

const manifestPath = resolve(REPO_ROOT, "build/woo-login.asset.php");
const bundlePath = resolve(REPO_ROOT, "build/woo-login.js");

let manifest = "";
let bundle = "";
try {
	manifest = readFileSync(manifestPath, "utf8");
	bundle = readFileSync(bundlePath, "utf8");
} catch (err) {
	console.error(`\n  Build output missing — run \`npm run build\` first.\n  ${err.message}\n`);
	process.exit(1);
}

t.check("manifest is a PHP array literal", /^<\?php return array\(/.test(manifest.trim()));
t.check(
	"manifest declares an empty dependency array",
	/'dependencies'\s*=>\s*array\(\s*\)/.test(manifest),
	"the bundle imports nothing WordPress registers as a handle",
);

const version = /'version'\s*=>\s*'([^']*)'/.exec(manifest)?.[1] ?? "";
t.check("manifest carries a content hash", version.length === 20, `version=${version || "(none)"}`);

t.check("bundle is an IIFE", bundle.trimStart().startsWith("(function()"));
t.check(
	"bundle builds DOM nodes rather than parsing markup",
	!bundle.includes("innerHTML"),
	"the label is a site-owner string interpolated into the page",
);
t.check(
	"bundle targets only the login form",
	bundle.includes("woocommerce-form-login") && !bundle.includes("wc-block-components-form"),
	"`.wc-block-components-form` is the checkout fields form, not a login form",
);
t.check("bundle knows the shared marker class", bundle.includes("jwt-auth-sso"));

console.log(t.failures ? `\n${t.failures} failure(s)\n` : "\nAll checks passed\n");
process.exit(t.failures ? 1 : 0);
