<?php

declare(strict_types=1);

namespace JwtAuth;

final class Config
{
    // -------------------------------------------------------------------------
    // Mode detection
    // -------------------------------------------------------------------------

    public static function detectMode(): AuthMode
    {
        return match (true) {
            defined('JWT_AUTH_CLIENT_ID') => AuthMode::Oidc,
            defined('JWT_AUTH_JWKS_URI')  => AuthMode::Proxy,
            default => throw new \RuntimeException(
                'JWT Auth: define JWT_AUTH_CLIENT_ID (OIDC) or JWT_AUTH_JWKS_URI (proxy) in wp-config.php'
            ),
        };
    }

    /**
     * Whether the site should sign people in with WordPress passwords and leave the provider out.
     *
     * True in a `local` or `development` environment (`WP_ENVIRONMENT_TYPE`), where the provider is
     * usually unreachable anyway: the callback URL is `http://127.0.0.1:<port>/…`, which no provider
     * has registered, so the OIDC flow could not complete even if the plugin intercepted the login
     * screen — it would only lock the developer out. `JWT_AUTH_NATIVE_LOGIN` overrides the
     * environment in either direction: `true` to stand down anywhere (a staging site without a
     * provider), `false` to exercise the provider flow from a development environment.
     */
    public static function nativeLogin(): bool
    {
        if (defined('JWT_AUTH_NATIVE_LOGIN')) {
            return (bool) JWT_AUTH_NATIVE_LOGIN;
        }
        return in_array(wp_get_environment_type(), ['local', 'development'], true);
    }

    // -------------------------------------------------------------------------
    // OIDC mode
    // -------------------------------------------------------------------------

    public static function issuer(): string
    {
        return defined('JWT_AUTH_ISSUER') ? JWT_AUTH_ISSUER : '';
    }

    public static function clientId(): string
    {
        return defined('JWT_AUTH_CLIENT_ID') ? JWT_AUTH_CLIENT_ID : '';
    }

    public static function clientSecret(): string
    {
        return defined('JWT_AUTH_CLIENT_SECRET') ? JWT_AUTH_CLIENT_SECRET : '';
    }

    // -------------------------------------------------------------------------
    // Proxy mode / shared overrides
    // -------------------------------------------------------------------------

    /** Explicit JWKS URI — overrides OIDC discovery when set. Required in proxy mode. */
    public static function jwksUri(): ?string
    {
        return defined('JWT_AUTH_JWKS_URI') ? JWT_AUTH_JWKS_URI : null;
    }

    /** Expected audience claim value. Required in proxy mode; overrides client_id check in OIDC mode when set. */
    public static function aud(): ?string
    {
        return defined('JWT_AUTH_AUD') ? JWT_AUTH_AUD : null;
    }

    /** Cookie name that carries the JWT (proxy mode). */
    public static function tokenCookie(): ?string
    {
        return defined('JWT_AUTH_TOKEN_COOKIE') ? JWT_AUTH_TOKEN_COOKIE : null;
    }

    /** HTTP header name that carries the JWT (proxy mode). */
    public static function tokenHeader(): ?string
    {
        return defined('JWT_AUTH_TOKEN_HEADER') ? JWT_AUTH_TOKEN_HEADER : null;
    }

    /** Provider logout URL. Overrides OIDC end_session_endpoint when set. */
    public static function logoutUrl(): ?string
    {
        return defined('JWT_AUTH_LOGOUT_URL') && JWT_AUTH_LOGOUT_URL !== '' ? JWT_AUTH_LOGOUT_URL : null;
    }

    // -------------------------------------------------------------------------
    // User creation
    // -------------------------------------------------------------------------

    /**
     * Demand a positive `email_verified: true` before an address may claim an existing account.
     *
     * Off by default so a provider that omits the claim keeps working — the companion worker never
     * issues an unverified address. Turn it on for any IdP with self-service signup, where an
     * attacker can register with somebody else's address and never confirm it.
     */
    public static function requireVerifiedEmail(): bool
    {
        return defined('JWT_AUTH_REQUIRE_VERIFIED_EMAIL') && JWT_AUTH_REQUIRE_VERIFIED_EMAIL;
    }

    public static function claimEmail(): string
    {
        return defined('JWT_AUTH_CLAIM_EMAIL') ? JWT_AUTH_CLAIM_EMAIL : 'email';
    }

    public static function claimFirstName(): string
    {
        return defined('JWT_AUTH_CLAIM_FIRST_NAME') ? JWT_AUTH_CLAIM_FIRST_NAME : 'given_name';
    }

    public static function claimLastName(): string
    {
        return defined('JWT_AUTH_CLAIM_LAST_NAME') ? JWT_AUTH_CLAIM_LAST_NAME : 'family_name';
    }

    public static function claimName(): string
    {
        return defined('JWT_AUTH_CLAIM_NAME') ? JWT_AUTH_CLAIM_NAME : 'name';
    }

    // -------------------------------------------------------------------------
    // UX
    // -------------------------------------------------------------------------

    /**
     * Whether native username/password forms are removed rather than merely refused.
     *
     * Off by default, and the difference is presentational rather than a security boundary:
     * Validator::blockDirectAuth() already refuses every credential, so a password box on a site
     * running this plugin is a control that cannot succeed. What it does buy is that visitors are
     * not offered a choice between two paths where only one works — and it closes the credential
     * flows WooCommerce runs *outside* the `authenticate` filter, which are a boundary. See
     * ExclusiveLogin.
     */
    public static function exclusive(): bool
    {
        return defined('JWT_AUTH_EXCLUSIVE') && JWT_AUTH_EXCLUSIVE;
    }

    public static function redirect(): string
    {
        return defined('JWT_AUTH_REDIRECT') ? JWT_AUTH_REDIRECT : '/';
    }

    public static function providerName(): string
    {
        return defined('JWT_AUTH_PROVIDER_NAME') ? JWT_AUTH_PROVIDER_NAME : 'SSO';
    }

    /** The URL the OIDC provider redirects back to after authentication. */
    public static function callbackUrl(): string
    {
        return add_query_arg('jwt_auth_callback', '1', home_url('/'));
    }
}
