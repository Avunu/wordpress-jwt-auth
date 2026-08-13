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
     *
     * Hooked LAST, not first (jwt-auth.php). `authenticate` is a filter, so its value is whatever
     * the final callback returns — running at priority 1 and handing back a WP_Error only blocks
     * the login if every later callback preserves it, and WordPress core's own handlers sit at
     * priority 20. Registering below them made this an advertised control that did nothing on the
     * paths that matter: XML-RPC, application passwords, and any direct wp_authenticate() call all
     * reach core's handler, which authenticates the credential and returns a WP_User, overwriting
     * the refusal. Running after core means we get the last word whatever it decided.
     *
     * The filter is seeded with null by wp_authenticate(), and a filter must be able to hand back
     * whatever it was given, so the return type has to admit null — declaring anything narrower
     * turns the WP-CLI/cron pass-through below into a fatal TypeError on the very path it exists
     * to keep working.
     */
    public static function blockDirectAuth(
        mixed $user,
        string $username,
        string $password,
    ): \WP_Error|\WP_User|null {
        if ((defined('WP_CLI') && WP_CLI) || wp_doing_cron()) {
            return $user;
        }

        // Nothing was submitted, so there is no credential to refuse. Hand back whatever core
        // produced — its "empty username" errors are better UX than a lecture about SSO, and
        // wp_authenticate() treats those codes specially.
        if ($username === '' && $password === '') {
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
        if ($user === null) {
            // Unknown person, registration closed. This hook runs on every unauthenticated request,
            // so failing loudly would take the public site down for them too. Stay anonymous, and
            // only explain on the requests whose whole purpose is getting signed in.
            if (Registration::isSignInRequest()) {
                Registration::deny();
            }
            return;
        }

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
