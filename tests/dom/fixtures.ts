// Markup lifted from the WooCommerce templates the plugin actually meets, trimmed to the parts the
// injector inspects (form classes and nesting). Keeping these honest is the point: the duplicate
// button existed precisely because the script's selectors were written against an imagined page
// rather than the rendered one.

/**
 * `templates/myaccount/form-login.php` — the classic My Account login form, as rendered when the
 * plugin's `woocommerce_login_form_start` callback has NOT run.
 */
export const MY_ACCOUNT_LOGIN_FORM = `
<div class="u-columns col2-set" id="customer_login">
	<div class="u-column1 col-1">
		<h2>Login</h2>
		<form class="woocommerce-form woocommerce-form-login login" method="post" novalidate>
			<p class="woocommerce-form-row form-row form-row-wide">
				<label for="username">Username or email address</label>
				<input type="text" name="username" id="username" />
			</p>
			<p class="woocommerce-form-row form-row form-row-wide">
				<label for="password">Password</label>
				<input type="password" name="password" id="password" />
			</p>
			<p class="form-row">
				<button type="submit" class="woocommerce-button button" name="login">Log in</button>
			</p>
		</form>
	</div>
	<div class="u-column2 col-2">
		<h2>Register</h2>
		<form method="post" class="woocommerce-form woocommerce-form-register register">
			<p class="woocommerce-form-row form-row form-row-wide">
				<label for="reg_email">Email address</label>
				<input type="email" name="email" id="reg_email" />
			</p>
		</form>
	</div>
</div>`;

/**
 * The same page with the server-rendered button in place — what a real My Account response looks
 * like, since `woocommerce_login_form_start` fires as the form's first child.
 */
export const MY_ACCOUNT_LOGIN_FORM_WITH_SERVER_BUTTON = MY_ACCOUNT_LOGIN_FORM.replace(
	'<form class="woocommerce-form woocommerce-form-login login" method="post" novalidate>',
	`<form class="woocommerce-form woocommerce-form-login login" method="post" novalidate>
			<div class="jwt-auth-sso"><a href="https://example.test/wp-login.php" class="woocommerce-button button">Sign in with SSO</a></div>`,
);

/**
 * `client/blocks/assets/js/base/components/form/index.tsx` — the block checkout's _fields_ form.
 * Despite the name it collects contact and address details; it is not a login form, and an earlier
 * selector list matched it, putting an SSO button in the middle of the address fields.
 */
export const BLOCK_CHECKOUT_FIELDS_FORM = `
<div class="wc-block-checkout">
	<form class="wc-block-components-form wc-block-checkout__contact-fields">
		<div class="wc-block-components-address-form">
			<input type="email" id="email" />
		</div>
	</form>
</div>`;

/**
 * `src/Blocks/BlockTypes/CustomerAccount.php` — the Customer Account block. It renders a link, and
 * never a form; the other stale selector (`.wp-block-woocommerce-customer-account form`) could
 * therefore never match anything.
 */
export const CUSTOMER_ACCOUNT_BLOCK = `
<div class="wp-block-woocommerce-customer-account">
	<a href="https://example.test/my-account/">
		<span class="label">My Account</span>
	</a>
</div>`;
