<?php
/**
 * App authorisation sign-in (/wc-auth/v1/authorize), with no password form.
 *
 * Substituted for woocommerce/templates/auth/form-login.php by ExclusiveLogin::wooTemplate() when
 * JWT_AUTH_EXCLUSIVE is on. This is the screen a mobile app or integration sends a shop owner to
 * before asking for REST API keys, and it is the login form people forget: WC_Auth::auth_endpoint()
 * knows a password box is wrong for a federated site — its own comment says so — but only redirects
 * around it for Jetpack SSO. Every other provider gets the form, and the form cannot work, because
 * the POST behind it ends in the `authenticate` filter.
 *
 * `$app_name`, `$return_url` and `$redirect_url` arrive extracted by wc_get_template(). Signing in
 * returns the browser to $redirect_url, which is the authorize step WC_Auth built — so the
 * integration's flow continues rather than dead-ending on a session it cannot use.
 *
 * @package JwtAuth
 *
 * @var string $app_name
 * @var string $return_url
 * @var string $redirect_url
 */

defined('ABSPATH') || exit;

do_action('woocommerce_auth_page_header');
?>

<h1><?php
	echo esc_html(sprintf('%s would like to connect to your store', wc_clean($app_name)));
?></h1>

<?php wc_print_notices(); ?>

<p><?php
	echo wp_kses_post(sprintf(
		'To connect to %1$s you need to be signed in. Sign in below, or <a href="%2$s">cancel and return to %1$s</a>.',
		esc_html(wc_clean($app_name)),
		esc_url($return_url),
	));
?></p>

<p class="wc-auth-actions">
	<?php echo \JwtAuth\SsoButton::html(wp_login_url($redirect_url), 'button button-large button-primary'); ?>
</p>

<?php do_action('woocommerce_auth_page_footer'); ?>
