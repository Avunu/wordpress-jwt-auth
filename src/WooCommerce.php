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
 */
final class WooCommerce
{
    /** Wrapper class shared by both injectors; the script uses it to detect this one. */
    private const MARKER_CLASS = 'jwt-auth-sso';

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

        echo self::buttonHtml(wp_login_url($redirectTo));
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
                'buttonLabel' => self::buttonLabel(),
            ]) . ';',
            'before',
        );
    }

    private static function buttonLabel(): string
    {
        return sprintf('Sign in with %s', Config::providerName());
    }

    private static function buttonHtml(string $url): string
    {
        return sprintf(
            '<div class="%s"><a href="%s" class="woocommerce-button button">%s</a></div>',
            esc_attr(self::MARKER_CLASS),
            esc_url($url),
            esc_html(self::buttonLabel()),
        );
    }
}
