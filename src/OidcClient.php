<?php

declare(strict_types=1);

namespace JwtAuth;

final class OidcClient
{
    private const DISCOVERY_PATH  = '/.well-known/openid-configuration';
    private const STATE_PREFIX    = 'jwt_auth_state_';
    private const VERIFIER_PREFIX = 'jwt_auth_cv_';
    private const TRANSIENT_TTL   = 600; // 10 minutes

    // -------------------------------------------------------------------------
    // OIDC discovery
    // -------------------------------------------------------------------------

    /** Returns the cached OIDC discovery document. Cached for 24 hours. */
    public static function discover(): array
    {
        $cacheKey = 'jwt_auth_disc_' . md5(Config::issuer());
        $cached   = get_transient($cacheKey);
        if ($cached !== false) return $cached;

        $url      = rtrim(Config::issuer(), '/') . self::DISCOVERY_PATH;
        $response = wp_remote_get($url, ['timeout' => 10]);

        if (is_wp_error($response)) {
            throw new \RuntimeException('OIDC discovery failed: ' . $response->get_error_message());
        }

        $doc = json_decode(wp_remote_retrieve_body($response), associative: true);

        if (empty($doc['authorization_endpoint'])) {
            throw new \RuntimeException('Invalid OIDC discovery document at ' . $url);
        }

        set_transient($cacheKey, $doc, DAY_IN_SECONDS);
        return $doc;
    }

    /** Returns the JWKS URI — explicit constant takes precedence over discovery. */
    public static function jwksUri(): string
    {
        return Config::jwksUri() ?? self::discover()['jwks_uri']
            ?? throw new \RuntimeException('JWKS URI not found in discovery document');
    }

    // -------------------------------------------------------------------------
    // login_init hook — redirect to provider
    // -------------------------------------------------------------------------

    public static function redirectToProvider(): void
    {
        $redirectTo = sanitize_url($_REQUEST['redirect_to'] ?? Config::redirect());
        $state      = self::generateState($redirectTo);
        $challenge  = self::generatePkce($state);
        $doc        = self::discover();

        wp_redirect($doc['authorization_endpoint'] . '?' . http_build_query([
            'response_type'         => 'code',
            'client_id'             => Config::clientId(),
            'redirect_uri'          => Config::callbackUrl(),
            'scope'                 => 'openid email profile',
            'state'                 => $state,
            'code_challenge'        => $challenge,
            'code_challenge_method' => 'S256',
        ]));
        exit;
    }

    // -------------------------------------------------------------------------
    // init hook (priority 1) — handle OIDC callback
    // -------------------------------------------------------------------------

    public static function handleCallback(): void
    {
        if (($_GET['jwt_auth_callback'] ?? '') !== '1') return;

        $code  = sanitize_text_field($_GET['code']  ?? '');
        $state = sanitize_text_field($_GET['state'] ?? '');

        if (!$code || !$state) {
            wp_die('Missing callback parameters.', 'Authentication Error', ['response' => 400]);
        }

        // Validate state (CSRF) — single-use transient
        $redirectTo = get_transient(self::STATE_PREFIX . $state);
        if ($redirectTo === false) {
            wp_die('Invalid or expired authentication state.', 'Authentication Error', ['response' => 400]);
        }
        delete_transient(self::STATE_PREFIX . $state);

        $verifier = get_transient(self::VERIFIER_PREFIX . $state);
        if ($verifier === false) {
            wp_die('Missing PKCE verifier.', 'Authentication Error', ['response' => 400]);
        }
        delete_transient(self::VERIFIER_PREFIX . $state);

        // Exchange code for tokens
        $tokens  = self::exchangeCode($code, $verifier);
        $idToken = $tokens['id_token'] ?? '';
        if (!$idToken) {
            wp_die('No ID token in provider response.', 'Authentication Error', ['response' => 502]);
        }

        // Validate ID token
        try {
            $claims = Validator::decode($idToken, self::jwksUri());
        } catch (\Throwable $e) {
            wp_die('Token validation failed: ' . esc_html($e->getMessage()), 'Authentication Error', ['response' => 401]);
        }

        // Validate standard claims
        if (Config::issuer() !== '' && $claims->iss !== Config::issuer()) {
            wp_die('Issuer mismatch.', 'Authentication Error', ['response' => 401]);
        }

        $expectedAud = Config::aud() ?? Config::clientId();
        if ($expectedAud !== '' && !$claims->hasAudience($expectedAud)) {
            wp_die('Audience mismatch.', 'Authentication Error', ['response' => 401]);
        }

        // Establish WordPress session
        $user = UserManager::findOrCreate($claims);
        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, remember: true);
        do_action('wp_login', $user->user_login, $user);

        wp_safe_redirect(wp_validate_redirect($redirectTo, home_url('/')));
        exit;
    }

    // -------------------------------------------------------------------------
    // wp_logout hook
    // -------------------------------------------------------------------------

    public static function handleLogout(): void
    {
        $logoutUrl = Config::logoutUrl();

        if ($logoutUrl === null && Config::issuer() !== '') {
            $endpoint = self::tryDiscover()['end_session_endpoint'] ?? null;
            if ($endpoint) {
                $logoutUrl = $endpoint . '?' . http_build_query([
                    'post_logout_redirect_uri' => home_url('/'),
                ]);
            }
        }

        if ($logoutUrl) {
            wp_redirect($logoutUrl);
            exit;
        }
    }

    // -------------------------------------------------------------------------
    // PKCE + state helpers
    // -------------------------------------------------------------------------

    private static function generateState(string $redirectTo): string
    {
        $state = bin2hex(random_bytes(16));
        set_transient(self::STATE_PREFIX . $state, $redirectTo ?: Config::redirect(), self::TRANSIENT_TTL);
        return $state;
    }

    private static function generatePkce(string $state): string
    {
        $verifier  = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, binary: true)), '+/', '-_'), '=');
        set_transient(self::VERIFIER_PREFIX . $state, $verifier, self::TRANSIENT_TTL);
        return $challenge;
    }

    private static function exchangeCode(string $code, string $verifier): array
    {
        $body = [
            'grant_type'    => 'authorization_code',
            'client_id'     => Config::clientId(),
            'code'          => $code,
            'redirect_uri'  => Config::callbackUrl(),
            'code_verifier' => $verifier,
        ];

        if (Config::clientSecret() !== '') {
            $body['client_secret'] = Config::clientSecret();
        }

        $response = wp_remote_post(self::discover()['token_endpoint'], [
            'body'    => $body,
            'timeout' => 15,
        ]);

        if (is_wp_error($response)) {
            wp_die('Token exchange failed: ' . esc_html($response->get_error_message()), 'Authentication Error', ['response' => 502]);
        }

        $data = json_decode(wp_remote_retrieve_body($response), associative: true);

        if (!empty($data['error'])) {
            wp_die(
                'Provider error: ' . esc_html($data['error_description'] ?? $data['error']),
                'Authentication Error',
                ['response' => 502],
            );
        }

        return $data;
    }

    /** Silent discovery attempt — returns empty array on failure (used for optional features like logout). */
    private static function tryDiscover(): array
    {
        try {
            return self::discover();
        } catch (\Throwable) {
            return [];
        }
    }
}
