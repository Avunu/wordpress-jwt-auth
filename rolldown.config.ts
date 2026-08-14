import { defineConfig } from "rolldown";
import type { Plugin } from "rolldown";
import { createHash } from "node:crypto";

/**
 * Build config for the WooCommerce sign-in button fallback script.
 *
 * Output is a single IIFE (`build/woo-login.js`) plus a WordPress dependency manifest
 * (`build/woo-login.asset.php`) — matching what WooCommerce::enqueueAssets() expects.
 *
 * There is no externalization layer here, unlike a @wordpress/scripts-style build: this bundle
 * imports nothing outside `assets/src`, so its dependency array is empty and every module is
 * bundled. The manifest is emitted anyway, for the content hash — it is what busts the browser
 * cache when the script changes, and hand-maintaining a version string is exactly the kind of thing
 * that silently stops happening.
 */

/** Emit `woo-login.asset.php` in WordPress's own format: dependency handles plus a content hash. */
function wpAssets(): Plugin {
	return {
		name: "wp-assets",
		generateBundle(_options, bundle) {
			let entryCode = "";
			for (const file of Object.values(bundle)) {
				if (file.type === "chunk" && file.isEntry) {
					entryCode = file.code;
				}
			}
			const version = createHash("sha256").update(entryCode).digest("hex").slice(0, 20);
			const php = `<?php return array('dependencies' => array(), 'version' => '${version}');\n`;

			this.emitFile({ type: "asset", fileName: "woo-login.asset.php", source: php });
		},
	};
}

export default defineConfig({
	input: "assets/src/woo-login.ts",
	platform: "browser",
	plugins: [wpAssets()],
	output: {
		dir: "build",
		format: "iife",
		entryFileNames: "woo-login.js",
		minify: true,
	},
});
