<?php

declare(strict_types=1);

namespace JwtAuth;

/**
 * The one affordance this plugin ever renders: "Sign in with {provider}".
 *
 * Extracted so the marker class exists in exactly one place in PHP. Three separate injectors emit
 * this markup — the WooCommerce login-form hook, the replacement templates JWT_AUTH_EXCLUSIVE
 * substitutes, and the core `wp_login_form()` filter pair — and the browser fallback in
 * `assets/src/sso-button.ts` decides whether to add its own by looking for this class. A second
 * definition of the string is a duplicate button on somebody's My Account page.
 */
final class SsoButton
{
    /** Wrapper class every injector emits; the fallback script uses it to detect the others. */
    public const MARKER_CLASS = 'jwt-auth-sso';

    public static function label(): string
    {
        return sprintf('Sign in with %s', Config::providerName());
    }

    /**
     * The button, wrapped in its marker.
     *
     * $linkClass is the theme's business rather than ours: WooCommerce buttons want
     * `woocommerce-button button`, a core login form wants plain `button`.
     */
    public static function html(string $loginUrl, string $linkClass = 'button'): string
    {
        return sprintf(
            '<div class="%s"><a href="%s" class="%s">%s</a></div>',
            esc_attr(self::MARKER_CLASS),
            esc_url($loginUrl),
            esc_attr($linkClass),
            esc_html(self::label()),
        );
    }
}
