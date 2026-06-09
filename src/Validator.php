<?php

declare(strict_types=1);

namespace JwtAuth;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

final class Validator
{
    private const LEEWAY = 60;

    // -------------------------------------------------------------------------
    // JWT decoding
    // -------------------------------------------------------------------------

    /**
     * Decodes a JWT string against a JWKS URI and returns structured claims.
     * Retries once with a fresh key fetch on signature failure (handles key rotation).
     */
    public static function decode(string $token, string $jwksUri): Claims
    {
        JWT::$leeway = self::LEEWAY;

        try {
            $payload = JWT::decode($token, JWK::parseKeySet(Jwks::get($jwksUri), 'RS256'));
        } catch (\UnexpectedValueException) {
            // Stale keys — retry with a forced refresh
            $payload = JWT::decode($token, JWK::parseKeySet(Jwks::refresh($jwksUri), 'RS256'));
        }

        return Claims::fromPayload($payload);
    }

    // -------------------------------------------------------------------------
    // WordPress authenticate filter (both modes)
    // -------------------------------------------------------------------------

    /**
     * Blocks all direct username/password authentication.
     * Hooked at priority 1 — fires before WP's own handlers.
     */
    public static function blockDirectAuth(mixed $user, string $username, string $password): \WP_Error|\WP_User
    {
        if ((defined('WP_CLI') && WP_CLI) || (defined('DOING_CRON') && DOING_CRON)) {
            return $user;
        }

        return new \WP_Error(
            'jwt_auth_required',
            sprintf(
                'Direct login is disabled. <a href="%s">Sign in with %s</a>.',
                esc_url(wp_login_url()),
                esc_html(Config::providerName()),
            ),
        );
    }

    // -------------------------------------------------------------------------
    // Proxy mode — validate JWT on every unauthenticated request
    // -------------------------------------------------------------------------

    public static function validateProxyJwt(): void
    {
        $token = self::extractToken();
        if ($token === null) return;

        if (is_user_logged_in()) return;

        $jwksUri = Config::jwksUri()
            ?? throw new \RuntimeException('JWT_AUTH_JWKS_URI must be defined in proxy mode');

        try {
            $claims = self::decode($token, $jwksUri);
        } catch (\Throwable) {
            return; // Invalid token — leave request unauthenticated
        }

        if (Config::aud() !== null && !$claims->hasAudience(Config::aud())) {
            return;
        }

        $user = UserManager::findOrCreate($claims);

        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, remember: true);
        do_action('wp_login', $user->user_login, $user);
    }

    // -------------------------------------------------------------------------
    // Token extraction helpers
    // -------------------------------------------------------------------------

    private static function extractToken(): ?string
    {
        // 1. Configured cookie
        $cookie = Config::tokenCookie();
        if ($cookie !== null && !empty($_COOKIE[$cookie])) {
            return $_COOKIE[$cookie];
        }

        // 2. Configured header
        $header = Config::tokenHeader();
        if ($header !== null) {
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
            if (!empty($_SERVER[$key])) {
                return $_SERVER[$key];
            }
        }

        // 3. Authorization: Bearer fallback
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (str_starts_with($auth, 'Bearer ')) {
            return substr($auth, 7);
        }

        return null;
    }
}
