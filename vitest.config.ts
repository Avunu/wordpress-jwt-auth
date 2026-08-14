import { defineConfig } from "vitest/config";

// The SSO button script runs in a browser, so these tests need a DOM. jsdom supplies the pieces
// the script actually uses — querySelector, MutationObserver, and element construction.
//
// Note what jsdom cannot tell you, and why the playground browser test exists alongside this
// suite: jsdom renders nothing, so "the button is visible" and "the PHP-rendered button and the
// script's are both in the document" are not questions it can answer against a real WooCommerce
// page. Here we assert the injection *rules*; tests/playground asserts the rendered result.
export default defineConfig({
	test: {
		include: ["tests/dom/**/*.test.ts"],
		environment: "jsdom",
	},
});
