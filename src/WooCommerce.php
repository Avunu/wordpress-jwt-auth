<?php

declare(strict_types=1);

namespace JwtAuth;

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

        echo self::buttonHtml(wp_login_url($redirectTo));
    }

    /**
     * Enqueues the block-form override script on My Account and Checkout pages.
     * Hooked to wp_enqueue_scripts.
     */
    public static function enqueueAssets(): void
    {
        if (Config::detectMode() !== AuthMode::Oidc) return;
        if (!function_exists('is_account_page')) return;
        if (!is_account_page() && !is_checkout()) return;

        $redirectTo = is_account_page()
            ? (wc_get_page_permalink('myaccount') ?: home_url('/'))
            : (wc_get_checkout_url() ?: home_url('/'));

        wp_enqueue_script(
            'jwt-auth-woo',
            plugin_dir_url(__DIR__) . 'assets/woo-login.js',
            [],
            '1.0.0',
            in_footer: true,
        );

        wp_localize_script('jwt-auth-woo', 'jwtAuth', [
            'loginUrl'    => wp_login_url($redirectTo),
            'buttonLabel' => sprintf('Sign in with %s', Config::providerName()),
        ]);
    }

    private static function buttonHtml(string $url): string
    {
        return sprintf(
            '<div class="jwt-auth-sso"><a href="%s" class="woocommerce-button button">%s</a></div>',
            esc_url($url),
            esc_html(sprintf('Sign in with %s', Config::providerName())),
        );
    }
}
