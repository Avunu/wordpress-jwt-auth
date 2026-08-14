<?php

declare(strict_types=1);

namespace JwtAuth;

/**
 * JWT_AUTH_EXCLUSIVE — take the password forms away instead of standing beside them.
 *
 * Without this switch the plugin refuses credentials but leaves the forms where they were: My
 * Account still shows "Username or email address" and "Password" above the SSO button, and the
 * WooCommerce checkout still offers "Returning customer? Click here to login". Nothing there can
 * succeed — Validator::blockDirectAuth() has the last word on `authenticate` — so what a visitor is
 * really being shown is two doors, one of which is painted on. This class removes the painted one.
 *
 * It is not only cosmetic, and that is the part worth reading twice. WooCommerce grants WordPress
 * sessions on two paths that never reach the `authenticate` filter at all:
 *
 *   - WC_Shortcode_My_Account::reset_password() ends in wc_set_customer_auth_cookie(). "Lost your
 *     password?" therefore signs the visitor in on the strength of access to an inbox, with the
 *     identity provider never consulted. On a site whose whole premise is federated login, that is
 *     a complete bypass, and no amount of filtering `authenticate` touches it.
 *   - WC_Form_Handler::process_registration() does the same for the Register column, minting a
 *     password nobody can ever use and a session nobody asked the provider about.
 *
 * So the strategy is layered rather than clever, and deliberately over-determined on those two:
 * refuse the reset key so it is never issued (`allow_password_reset`), add an error on the
 * documented extension points so a handler that still runs declines, and drop WooCommerce's own
 * hooks so it does not run. Any one of the three would do; all three survive one of the others
 * being defeated by a WooCommerce refactor.
 *
 * What is deliberately left alone: wp-login.php's `postpass`, `confirmaction`,
 * `confirm_admin_email`, recovery mode and `logout` actions (none of them take a login credential,
 * and blocking them breaks password-protected posts, privacy requests and the way out), and
 * everything an administrator does from wp-admin. Setting a user's password there stays possible and
 * stays useless, which is the correct combination.
 */
final class ExclusiveLogin
{
    /**
     * The wp-login.php actions that exist to take a credential.
     *
     * wp-login.php is not only the sign-in screen; `$default_actions` in core lists a dozen things
     * it does, including verifying post passwords and confirming privacy-policy requests. Blocking
     * the screen wholesale breaks features that have nothing to do with authentication, so this
     * names the ones that do.
     */
    private const CREDENTIAL_ACTIONS = [
        'login',
        'register',
        'lostpassword',
        'retrievepassword',
        'resetpass',
        'rp',
    ];

    /**
     * WooCommerce templates replaced wholesale, each mirrored under `templates/woocommerce/`.
     *
     * Every one of these renders a username/password field, and between them they are every such
     * field WooCommerce itself produces: My Account, the classic checkout and the `global/` form it
     * shares with the pay and order-received pages, the two halves of the password-reset flow, and
     * the app-authorisation screen behind /wc-auth/v1 (which WooCommerce only special-cases for
     * Jetpack SSO, so every other provider gets a password box there).
     *
     * Substituting the path rather than filtering the output is what makes this exhaustive: it wins
     * over a theme's own `woocommerce/myaccount/form-login.php` override too, and a theme override
     * is exactly where a stray password form would otherwise survive.
     */
    private const WOO_TEMPLATES = [
        'myaccount/form-login.php',
        'myaccount/form-lost-password.php',
        'myaccount/form-reset-password.php',
        'global/form-login.php',
        'checkout/form-login.php',
        'auth/form-login.php',
    ];

    public static function register(): void
    {
        // ---------------------------------------------------------------------
        // WordPress core
        // ---------------------------------------------------------------------

        // Any theme or plugin calling wp_login_form(), and core's own Login/out block.
        add_filter('login_form_top', self::openReplacement(...), 99, 2);
        add_filter('login_form_bottom', self::closeReplacement(...), 1);
        add_filter('render_block_data', self::demoteLoginBlock(...));

        // wp-login.php itself, for the requests that get past the redirect.
        add_action('login_init', self::blockLoginScreen(...), 20);

        // Password reset is a session grant here, not a form. Refusing the key stops it at source:
        // both core's retrieve_password() and WooCommerce's own copy of it ask this filter before
        // calling get_password_reset_key(), so nothing downstream ever gets a key to redeem.
        add_filter('allow_password_reset', '__return_false');
        add_action('lostpassword_post', self::refuseLostPassword(...));

        // ---------------------------------------------------------------------
        // WooCommerce
        // ---------------------------------------------------------------------

        if (!class_exists('WooCommerce')) return;

        add_filter('wc_get_template', self::wooTemplate(...), 10, 2);

        // The "create an account" checkbox on both checkouts (classic reads this filter via
        // WC_Checkout::is_registration_enabled(); the Store API route reads the same method). It
        // mints a password and calls wc_set_customer_auth_cookie(), so it is a second credential
        // path rather than a convenience. Priority 100 because WC_Checkout's own setter registers
        // __return_true/__return_false at priority 0.
        add_filter('woocommerce_checkout_registration_enabled', '__return_false', 100);

        // The order-confirmation "Create an account with …" block, which has no filter of its own —
        // only this option, and it defaults to 'yes' when absent, hence both filter names.
        add_filter('option_woocommerce_enable_delayed_account_creation', self::optionNo(...));
        add_filter('default_option_woocommerce_enable_delayed_account_creation', self::optionNo(...));

        add_filter('woocommerce_process_registration_errors', self::refuseWooRegistration(...));

        self::removeWooCredentialHandlers();
    }

    // -------------------------------------------------------------------------
    // Core: wp_login_form()
    // -------------------------------------------------------------------------

    /**
     * Replace the fields of a core login form with the SSO button. Hooked to login_form_top.
     *
     * `wp_login_form()` builds its markup as one string and offers no hook that can suppress the
     * username and password fields — `login_form_top`, `_middle` and `_bottom` inject *into* that
     * string, and `echo` is decided by the caller. So the fields cannot be removed; they can only be
     * put somewhere a browser will not render, submit or autofill them, and `<template>` is the one
     * element whose contents are inert on all three counts.
     *
     * The result parses as: an empty form, the button, then a `<template>` holding the fields. Core
     * appends its own `</form>` after login_form_bottom, which lands with no form open — an HTML5
     * parse error that every parser handles by ignoring the token, which is why closing the form
     * early here is safe rather than merely tidy.
     *
     * Priority 99 so another plugin's `login_form_top` content stays inside the real form element
     * instead of being swallowed by the template.
     *
     * @param mixed $content Content accumulated by earlier filters.
     * @param mixed $args    The parsed wp_login_form() arguments.
     */
    public static function openReplacement(mixed $content, mixed $args): string
    {
        $redirect = is_array($args) && is_string($args['redirect'] ?? null) ? $args['redirect'] : '';

        return (is_string($content) ? $content : '')
            . '</form>'
            . SsoButton::html(wp_login_url($redirect))
            . '<template class="jwt-auth-suppressed-login">';
    }

    /** Closes the inert wrapper openReplacement() started. Hooked to login_form_bottom. */
    public static function closeReplacement(mixed $content): string
    {
        // Priority 1 and a prepend, so anything another plugin appends here lands outside the
        // template and stays visible — a "Register" link below the button is not a password field.
        return '</template>' . (is_string($content) ? $content : '');
    }

    /**
     * Turn core's Login/out block back into a link. Hooked to render_block_data.
     *
     * The block has a "Display login as form" toggle; when it is on, render_block_core_loginout()
     * calls wp_login_form() and the visitor gets password fields inside a block theme. Clearing the
     * attribute before render drops it to wp_loginout() — a plain link to wp-login.php, which is
     * where the provider redirect already lives. Handling it here rather than leaning on the
     * `login_form_top` pair above keeps the block's own markup and classes intact.
     *
     * @param mixed $parsed The parsed block, as WP_Block_Parser produced it.
     */
    public static function demoteLoginBlock(mixed $parsed): mixed
    {
        if (!is_array($parsed) || ($parsed['blockName'] ?? null) !== 'core/loginout') {
            return $parsed;
        }

        if (!is_array($parsed['attrs'] ?? null)) {
            $parsed['attrs'] = [];
        }
        $parsed['attrs']['displayLoginAsForm'] = false;

        return $parsed;
    }

    // -------------------------------------------------------------------------
    // Core: wp-login.php
    // -------------------------------------------------------------------------

    /**
     * Refuse the sign-in screen rather than render a form it cannot honour. Hooked to login_init, 20.
     *
     * In OIDC mode this is only reached when OidcClient::redirectToProvider() gave up, which it does
     * on a discovery failure — a live HTTP call to the provider, so an outage there is a normal
     * event rather than a bug. Falling through to core's form is safe without this switch, because
     * blockDirectAuth() still refuses everything; with the switch on, a password box is exactly the
     * thing the site has promised not to show, so say what happened instead.
     *
     * In proxy mode there is no redirect registered at all: the upstream authenticates every request
     * before WordPress sees it, and this screen has never had a credential it could accept.
     */
    public static function blockLoginScreen(): void
    {
        $action = is_string($_REQUEST['action'] ?? null) ? $_REQUEST['action'] : 'login';

        if (!in_array($action, self::CREDENTIAL_ACTIONS, true)) return;

        if (Config::detectMode() === AuthMode::Oidc) {
            wp_die(
                sprintf(
                    'Sign-in is temporarily unavailable: %s could not be reached. Please try again shortly.',
                    esc_html(Config::providerName()),
                ),
                'Sign-in Unavailable',
                ['response' => 503],
            );
        }

        wp_die(
            sprintf(
                'This site does not use passwords. Access is managed by %s.',
                esc_html(Config::providerName()),
            ),
            'Sign-in Not Available',
            ['response' => 403],
        );
    }

    // -------------------------------------------------------------------------
    // Password reset
    // -------------------------------------------------------------------------

    /**
     * Decline a reset request on the documented extension point. Hooked to lostpassword_post.
     *
     * `allow_password_reset` already stops the key being minted, but its refusal surfaces as
     * WooCommerce's "Password reset is not allowed for this user" — which describes a per-user
     * restriction that is not what is happening. Adding the error here replaces that with the true
     * reason and a way forward, on a hook core and WooCommerce both consult.
     *
     * @param mixed $errors The WP_Error the caller accumulates into.
     */
    public static function refuseLostPassword(mixed $errors): void
    {
        if ($errors instanceof \WP_Error) {
            $errors->add('jwt_auth_required', self::signInInstead());
        }
    }

    // -------------------------------------------------------------------------
    // WooCommerce
    // -------------------------------------------------------------------------

    /**
     * Substitute this plugin's template for a WooCommerce credential form. Hooked to wc_get_template.
     *
     * `wc_get_template` rather than `woocommerce_locate_template`: the latter's result is written to
     * the object cache, so toggling JWT_AUTH_EXCLUSIVE on a site with a persistent cache would keep
     * serving whichever template was resolved first. This filter is applied after the cache read.
     *
     * @param mixed $template Absolute path WooCommerce resolved.
     * @param mixed $name     Template name, e.g. `myaccount/form-login.php`.
     */
    public static function wooTemplate(mixed $template, mixed $name): mixed
    {
        if (!is_string($template) || !is_string($name)) return $template;
        if (!in_array($name, self::WOO_TEMPLATES, true)) return $template;

        $replacement = plugin_dir_path(__DIR__) . 'templates/woocommerce/' . $name;

        // wc_get_template() renders *nothing* when the filtered path does not exist, so a checkout
        // missing templates/ must fall back to WooCommerce's own form rather than blank the page.
        // Only the zip build guarantees the directory is there.
        return is_file($replacement) ? $replacement : $template;
    }

    /**
     * Decline WooCommerce's own registration handler. Hooked to woocommerce_process_registration_errors.
     *
     * The Register column is gone with the template, so nothing on the site posts here — but
     * WC_Form_Handler::process_registration() reads only the nonce and the POST body, not the
     * setting that draws the form, so a crafted request still reaches wc_create_new_customer() and
     * the wc_set_customer_auth_cookie() call after it.
     *
     * @param mixed $errors The WP_Error WooCommerce accumulates validation failures into.
     */
    public static function refuseWooRegistration(mixed $errors): mixed
    {
        if ($errors instanceof \WP_Error) {
            $errors->add('jwt_auth_required', self::signInInstead());
        }
        return $errors;
    }

    /** Force a WooCommerce yes/no option off. */
    public static function optionNo(mixed $value): string
    {
        return 'no';
    }

    /**
     * Unhook the WooCommerce handlers that hand out sessions and passwords.
     *
     * WC_Form_Handler::init() runs while WooCommerce's plugin file is being included — before
     * `plugins_loaded`, where this runs — so these are registered by now and removable.
     *
     * process_login() is deliberately left in place: it ends in wp_signon() and is therefore
     * already refused, and keeping it means a third-party or AJAX login form that posts there still
     * gets blockDirectAuth()'s "sign in with …" notice rather than silence.
     */
    private static function removeWooCredentialHandlers(): void
    {
        remove_action('wp_loaded', ['WC_Form_Handler', 'process_registration'], 20);
        remove_action('wp_loaded', ['WC_Form_Handler', 'process_lost_password'], 20);
        remove_action('wp_loaded', ['WC_Form_Handler', 'process_reset_password'], 20);
        remove_action('template_redirect', ['WC_Form_Handler', 'redirect_reset_password_link']);
    }

    // -------------------------------------------------------------------------
    // Shared copy
    // -------------------------------------------------------------------------

    /** The sentence every refusal in this class ends with. */
    public static function signInInstead(): string
    {
        return sprintf(
            'This site does not use passwords. <a href="%s">Sign in with %s</a> instead.',
            esc_url(wp_login_url()),
            esc_html(Config::providerName()),
        );
    }
}
