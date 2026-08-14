// Ambient global augmentation (no imports/exports keeps this a script file, so the Window merge
// applies globally without `declare global`).

/** Shape of the config WooCommerce::enqueueAssets() writes via wp_add_inline_script. */
interface JwtAuthConfig {
	/** The `wp_login_url()` result, with the post-login destination already folded in. */
	loginUrl: string;
	/** "Sign in with {JWT_AUTH_PROVIDER_NAME}", already translated server-side. */
	buttonLabel: string;
	/**
	 * JWT_AUTH_EXCLUSIVE. When true the injector _replaces_ a form's contents rather than prepending
	 * to them: in exclusive mode every form WooCommerce renders has already been swapped server-side,
	 * so anything left for the script to find is a theme's or a modal's, and adding a button beside
	 * its password fields would put back the choice the switch removes.
	 */
	exclusive: boolean;
}

interface Window {
	/**
	 * Injected by WooCommerce::enqueueAssets(). Optional on purpose: the script is enqueued in the
	 * footer and must not assume the inline `before` script ran, nor that a third party left the
	 * global intact.
	 */
	jwtAuth?: JwtAuthConfig;
}
