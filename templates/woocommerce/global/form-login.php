<?php
/**
 * The shared WooCommerce login form, with no password fields.
 *
 * Substituted for woocommerce/templates/global/form-login.php by ExclusiveLogin::wooTemplate() when
 * JWT_AUTH_EXCLUSIVE is on. woocommerce_login_form() renders that template from the pay-for-order
 * and order-received pages, and from any theme or extension that calls the function directly.
 *
 * `$message`, `$redirect` and `$hidden` arrive extracted by wc_get_template().
 *
 * Still a `<form>`, and still carrying `login` and `woocommerce-form-login`, even though it now has
 * nothing to submit. Those two classes are a contract with code that does not know this template was
 * swapped: WooCommerce's checkout script reveals `form.login, form.woocommerce-form-login` when a
 * caller passed `hidden => true`, themes style the wrapper by those names, and the plugin's own
 * browser fallback keys on the same selector — where it finds the marker already present and leaves
 * the form alone. There is no submit control and no text input, so the empty form cannot be
 * submitted, implicitly or otherwise.
 *
 * @package JwtAuth
 *
 * @var string $message
 * @var string $redirect
 * @var bool   $hidden
 */

defined('ABSPATH') || exit;

if (is_user_logged_in()) {
	return;
}

$jwtAuthRedirect = is_string($redirect ?? null) && $redirect !== '' ? $redirect : home_url('/');
?>
<form class="woocommerce-form woocommerce-form-login login jwt-auth-login" method="post" <?php echo !empty($hidden) ? 'style="display:none;"' : ''; ?>>

	<?php
	if (is_string($message ?? null) && $message !== '') {
		echo wpautop(wptexturize($message)); // phpcs:ignore WordPress.Security.EscapeOutput -- caller-supplied copy, as in the template this replaces.
	}
	?>

	<?php echo \JwtAuth\SsoButton::html(wp_login_url($jwtAuthRedirect), 'woocommerce-button button'); ?>

</form>
