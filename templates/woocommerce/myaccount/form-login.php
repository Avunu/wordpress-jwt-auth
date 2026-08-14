<?php
/**
 * My Account sign-in, with no password form.
 *
 * Substituted for woocommerce/templates/myaccount/form-login.php by ExclusiveLogin::wooTemplate()
 * when JWT_AUTH_EXCLUSIVE is on, in place of a template that renders a username/password form and —
 * when registration is enabled — a second column asking for a password to sign up with. Neither can
 * succeed on this site, so neither is drawn.
 *
 * The surrounding actions are kept. Plugins print notices and account links from
 * woocommerce_before_customer_login_form / woocommerce_after_customer_login_form, and those have
 * nothing to do with passwords. woocommerce_login_form_start is *not* fired: it is where
 * WooCommerce::renderSsoButton() hooks, and firing it here would put a second button on the page.
 *
 * @package JwtAuth
 */

defined('ABSPATH') || exit;

do_action('woocommerce_before_customer_login_form');

$jwtAuthLoginUrl = wp_login_url(wc_get_page_permalink('myaccount') ?: home_url('/'));
?>

<div class="u-columns" id="customer_login">
	<div class="u-column1 col-1">

		<h2><?php echo esc_html(\JwtAuth\SsoButton::label()); ?></h2>

		<p>
			<?php
			echo esc_html(sprintf(
				'This store does not use passwords. Sign in with %s to see your orders and account details.',
				\JwtAuth\Config::providerName(),
			));
			?>
		</p>

		<?php echo \JwtAuth\SsoButton::html($jwtAuthLoginUrl, 'woocommerce-button button'); ?>

	</div>
</div>

<?php do_action('woocommerce_after_customer_login_form'); ?>
