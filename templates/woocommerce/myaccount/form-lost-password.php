<?php
/**
 * "Lost your password?" — explained rather than offered.
 *
 * Substituted for woocommerce/templates/myaccount/form-lost-password.php by
 * ExclusiveLogin::wooTemplate() when JWT_AUTH_EXCLUSIVE is on.
 *
 * The form this replaces was not merely useless, it was the way around the plugin:
 * WC_Shortcode_My_Account::reset_password() calls wc_set_customer_auth_cookie() once a new password
 * is set, so completing WooCommerce's reset flow signed a visitor in on the strength of inbox access
 * alone, with the identity provider never asked. Nothing in the `authenticate` filter sees that path.
 * The form is gone, the reset key is refused before it is minted, and WooCommerce's handlers for
 * both halves of the flow are unhooked — see ExclusiveLogin.
 *
 * Reachable at all only because WooCommerce points `lostpassword_url` at this endpoint, so an old
 * link or a bookmark still lands here.
 *
 * @package JwtAuth
 */

defined('ABSPATH') || exit;

do_action('woocommerce_before_lost_password_form');
?>

<p><?php
	echo esc_html(sprintf(
		'This store has no passwords to reset. Your account is held by %s — sign in there, or use its own account-recovery options.',
		\JwtAuth\Config::providerName(),
	));
?></p>

<?php echo \JwtAuth\SsoButton::html(wp_login_url(wc_get_page_permalink('myaccount') ?: home_url('/')), 'woocommerce-button button'); ?>

<?php do_action('woocommerce_after_lost_password_form'); ?>
