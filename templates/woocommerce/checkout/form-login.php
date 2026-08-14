<?php
/**
 * Checkout sign-in prompt, with no password form.
 *
 * Substituted for woocommerce/templates/checkout/form-login.php by ExclusiveLogin::wooTemplate()
 * when JWT_AUTH_EXCLUSIVE is on. WooCommerce's version prints "Returning customer? Click here to
 * login" and a hidden username/password form the link reveals; this prints the same invitation with
 * the button behind it directly, since there is nothing left to reveal and no reason to make a
 * returning customer click twice.
 *
 * The gate is WooCommerce's own setting, unchanged: a merchant who turned the checkout login
 * reminder off asked for no sign-in prompt here, and that answer does not become different because
 * the prompt is now an SSO button. The registration branch of the original template is gone —
 * `woocommerce_checkout_registration_enabled` is filtered false in exclusive mode.
 *
 * @package JwtAuth
 */

defined('ABSPATH') || exit;

if (is_user_logged_in()) {
	return;
}

if ('yes' !== get_option('woocommerce_enable_checkout_login_reminder')) {
	return;
}

$jwtAuthButton = \JwtAuth\SsoButton::html(
	wp_login_url(wc_get_checkout_url() ?: home_url('/')),
	'woocommerce-button button',
);
?>
<div class="woocommerce-form-login-toggle">
	<?php
	// Escape the default before filtering, then trust the result — the order WooCommerce's own
	// template uses, so a site that added markup through this filter is not double-escaped here.
	wc_print_notice(
		apply_filters('woocommerce_checkout_login_message', esc_html('Returning customer?'))
			. ' ' . $jwtAuthButton,
		'notice',
	);
	?>
</div>
