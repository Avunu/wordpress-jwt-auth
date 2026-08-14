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
