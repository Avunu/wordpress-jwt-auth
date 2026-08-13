<?php

declare(strict_types=1);

namespace JwtAuth;

/**
 * Whether this site mints accounts for people the provider vouches for, and what they are told
 * when it does not.
 *
 * The switch is WordPress's own Settings → General → "Anyone can register" rather than another
 * JWT_AUTH_* constant: the plugin already redirects wp-login.php's registration screen to the
 * provider, so the core setting had no remaining meaning here and now carries the one that matters.
 */
final class Registration
{
    private const MESSAGE = 'This site is not accepting new accounts. If you believe you should have access, contact the site administrator.';

    /** Whether WordPress is accepting new accounts — Settings → General → "Anyone can register". */
    public static function isOpen(): bool
    {
        return (bool) get_option('users_can_register');
    }

    /**
     * Whether this request exists to get somebody signed in — wp-admin or wp-login.php.
     *
     * Proxy mode validates a token on every unauthenticated request, so a refused visitor has to be
     * left anonymous on the public site rather than met with an error page everywhere. This marks
     * the requests where being silently anonymous is the confusing answer and deny() is the right
     * one. admin-ajax.php reports is_admin(), and halting there would hand JavaScript an error page
     * in place of its JSON, so it is excluded along with the non-browser contexts.
     */
    public static function isSignInRequest(): bool
    {
        if (wp_doing_ajax() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
            return false;
        }

        // Never stand between a visitor and the logout they asked for.
        if (($_REQUEST['action'] ?? '') === 'logout') {
            return false;
        }

        return is_admin() || ($GLOBALS['pagenow'] ?? '') === 'wp-login.php';
    }

    /**
     * Renders the notice and halts.
     *
     * Offers the provider sign-out link when one is configured. That is the only lever available in
     * proxy mode, where the upstream owns the session, and the fallback in OIDC mode when the
     * provider advertises no end-session endpoint to bounce through.
     */
    public static function deny(): never
    {
        $message   = self::MESSAGE;
        $logoutUrl = Config::logoutUrl();

        if ($logoutUrl !== null) {
            $message .= sprintf(
                ' <a href="%s">Sign out of %s</a>.',
                esc_url($logoutUrl),
                esc_html(Config::providerName()),
            );
        }

        wp_die($message, 'Registration Closed', ['response' => 403]);
    }
}
