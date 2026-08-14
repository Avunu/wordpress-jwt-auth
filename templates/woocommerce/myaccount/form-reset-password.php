<?php
/**
 * The second half of WooCommerce's password reset, refused.
 *
 * Substituted for woocommerce/templates/myaccount/form-reset-password.php by
 * ExclusiveLogin::wooTemplate() when JWT_AUTH_EXCLUSIVE is on.
 *
 * Normally unreachable in exclusive mode — WooCommerce only renders it once a valid reset key has
 * been redeemed, and `allow_password_reset` stops one being issued. The case this exists for is a key
 * minted *before* the switch was turned on: core reset keys stay valid for a day, so for that long
 * there can be a live link into a flow that ends in wc_set_customer_auth_cookie(). Replacing the
 * template means the form is not there to submit, and the handler behind it is unhooked besides.
 *
 * @package JwtAuth
 */

defined('ABSPATH') || exit;

do_action('woocommerce_before_reset_password_form');
?>

<p><?php
	echo esc_html(sprintf(
		'This link is no longer usable: this store has no passwords. Sign in with %s instead.',
		\JwtAuth\Config::providerName(),
	));
?></p>

<?php echo \JwtAuth\SsoButton::html(wp_login_url(wc_get_page_permalink('myaccount') ?: home_url('/')), 'woocommerce-button button'); ?>

<?php do_action('woocommerce_after_reset_password_form'); ?>
