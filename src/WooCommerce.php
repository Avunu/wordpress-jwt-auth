<?php

declare(strict_types=1);

namespace JwtAuth;

/**
 * The "Sign in with …" button on WooCommerce login forms.
 *
 * Two injectors, with a clear division of labour. PHP owns every form WooCommerce itself renders:
 * `woocommerce_login_form_start` fires inside the classic login form in both templates that
 * produce one (`myaccount/form-login.php` and `global/form-login.php`, the latter reached from
 * checkout and the pay/order-received pages), so My Account and Checkout are covered server-side
 * and the button survives with JavaScript switched off.
 *
 * The script is the fallback for what a server-rendered hook cannot see: a login form injected
 * after the response by an AJAX-rendering theme or a modal. It skips any form that already
 * contains the marker, so on an ordinary page it adds nothing.
 *
 * This is the *additive* integration: a button beside the password fields, which the plugin refuses
 * anyway. JWT_AUTH_EXCLUSIVE swaps the templates out from under WooCommerce instead, so no password
 * field is rendered at all — see ExclusiveLogin. Both hooks below stay registered either way:
 * renderSsoButton() then only fires for forms this plugin did not replace, which means a third
 * party's, and the script's fallback still has late-rendered forms to reach.
 */
final class WooCommerce
{
    /**
     * Outputs an SSO button at the top of the classic WooCommerce login form.
     * Hooked to woocommerce_login_form_start.
     */
    public static function renderSsoButton(): void
    {
        // In proxy mode users are automatically authenticated — no button needed.
        if (Config::detectMode() !== AuthMode::Oidc) return;

        $redirectTo = function_exists('is_account_page') && is_account_page()
            ? (wc_get_page_permalink('myaccount') ?: home_url('/'))
            : home_url('/');

        echo SsoButton::html(wp_login_url($redirectTo), 'woocommerce-button button');
    }

    /**
     * Enqueues the late-rendered-form fallback script on My Account and Checkout pages.
     * Hooked to wp_enqueue_scripts.
     */
    public static function enqueueAssets(): void
    {
        if (Config::detectMode() !== AuthMode::Oidc) return;
        if (!function_exists('is_account_page')) return;
        if (!is_account_page() && !is_checkout()) return;

        $dir = plugin_dir_path(__DIR__);
        $url = plugin_dir_url(__DIR__);

        // A source checkout that has not run `npm run build` has no bundle. Bail rather than
        // enqueue a 404: the server-rendered button already covers every form WooCommerce
        // renders, so a missing fallback costs nothing, while a broken script URL is a console
        // error on every My Account page view.
        $assetFile = $dir . 'build/woo-login.asset.php';
        if (!is_file($assetFile) || !is_file($dir . 'build/woo-login.js')) return;

        /** @var array{dependencies: array<int, string>, version: string} $asset */
        $asset = require $assetFile;

        $redirectTo = is_account_page()
            ? (wc_get_page_permalink('myaccount') ?: home_url('/'))
            : (wc_get_checkout_url() ?: home_url('/'));

        wp_enqueue_script(
            'jwt-auth-woo',
            $url . 'build/woo-login.js',
            $asset['dependencies'],
            $asset['version'],
            ['in_footer' => true],
        );

        // wp_add_inline_script(…, 'before') rather than wp_localize_script: the latter stringifies
        // every value and attaches a bare global, while this writes the object the script's
        // `window.jwtAuth` type actually describes (see types/globals.d.ts). The shape here must
        // stay in step with JwtAuthConfig there.
        wp_add_inline_script(
            'jwt-auth-woo',
            'window.jwtAuth = ' . wp_json_encode([
                'loginUrl'    => wp_login_url($redirectTo),
                'buttonLabel' => SsoButton::label(),
                // Under JWT_AUTH_EXCLUSIVE the script replaces a late-rendered form's contents
                // instead of prepending to them. Every form WooCommerce renders itself is already
                // gone by then — ExclusiveLogin substitutes the templates — so anything the script
                // still finds came from a theme or a modal, and prepending a button to it would
                // reintroduce exactly the choice the switch exists to remove.
                'exclusive'   => Config::exclusive(),
            ]) . ';',
            'before',
        );
    }
}
