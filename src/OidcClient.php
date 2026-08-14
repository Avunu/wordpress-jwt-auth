<?php

declare(strict_types=1);

namespace JwtAuth;

final class OidcClient
{
    private const DISCOVERY_PATH  = '/.well-known/openid-configuration';
    private const STATE_PREFIX    = 'jwt_auth_state_';
    private const VERIFIER_PREFIX = 'jwt_auth_cv_';
    private const TRANSIENT_TTL   = 600; // 10 minutes
    /** Browser-held secret proving a callback belongs to the browser that started the flow. */
    private const STATE_COOKIE    = 'jwt_auth_state_binder';

    // -------------------------------------------------------------------------
    // OIDC discovery
    // -------------------------------------------------------------------------

    /**
     * Returns the cached OIDC discovery document. Cached for 24 hours.
     *
     * @return array<string, mixed>
     */
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
        // Let WordPress's native logout flow run instead: it must destroy the session and clear
        // the auth cookie before wp_logout() fires our handleLogout(), which then redirects to the
        // provider's end-session endpoint. Redirecting here first would skip that entirely, leaving
        // the user's WordPress session intact while bouncing them to the sign-in screen.
        if (($_REQUEST['action'] ?? '') === 'logout') return;

        $redirectTo = sanitize_url($_REQUEST['redirect_to'] ?? Config::redirect());
        $state      = self::generateState($redirectTo);
        $challenge  = self::generatePkce($state);

        // Discovery is a live HTTP call to the provider, on an endpoint anyone can reach without
        // authenticating. Letting it throw turns "the IdP is briefly unreachable" into an uncaught
        // exception on wp-login.php — a 500, or with display_errors on, a stack trace carrying
        // absolute filesystem paths to any passer-by.
        //
        // Returning instead lets wp-login.php render its ordinary form. That is safe here precisely
        // because it is not the only defence: Validator::blockDirectAuth() still refuses every
        // username/password submission, so the fallback is a login page that cannot log anyone in,
        // rather than a way around SSO.
        try {
            $doc = self::discover();
        } catch (\RuntimeException $e) {
            error_log('JWT Auth: OIDC discovery failed on login, falling through: ' . $e->getMessage());
            return;
        }

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

        // Validate state (CSRF) — single-use transient, bound to the browser that started the flow.
        $record = get_transient(self::STATE_PREFIX . $state);
        $binder = (string) ($_COOKIE[self::STATE_COOKIE] ?? '');
        self::clearStateCookie();

        if ($record === false) {
            wp_die('Invalid or expired authentication state.', 'Authentication Error', ['response' => 400]);
        }
        delete_transient(self::STATE_PREFIX . $state);

        // A state minted in another browser is not this browser's sign-in, whatever else is valid
        // about it. hash_equals because the comparison is against a secret.
        if (!is_array($record)
            || $binder === ''
            || !hash_equals((string) ($record['binder'] ?? ''), hash('sha256', $binder))
        ) {
            delete_transient(self::VERIFIER_PREFIX . $state);
            wp_die('Invalid or expired authentication state.', 'Authentication Error', ['response' => 400]);
        }

        $redirectTo = (string) $record['redirect_to'];

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
        if ($user === null) {
            self::denyRegistration();
        }

        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, remember: true);
        do_action('wp_login', $user->user_login, $user);

        wp_safe_redirect(wp_validate_redirect($redirectTo, home_url('/')));
        exit;
    }

    // -------------------------------------------------------------------------
    // Registration closed
    // -------------------------------------------------------------------------

    /**
     * The provider authenticated someone this site will not create an account for.
     *
     * Prefer the round trip through the provider's end-session endpoint: ending its session means
     * the next attempt lands on an account chooser instead of silently replaying the same rejected
     * identity, and post_logout_redirect_uri brings the browser back here to be told why. A custom
     * JWT_AUTH_LOGOUT_URL cannot promise that return trip, so fall through and show the notice now
     * — Registration::deny() offers sign-out as a link instead.
     */
    private static function denyRegistration(): never
    {
        // No session was established, but a stale cookie from a previous identity must not survive
        // a sign-in the site just refused.
        wp_clear_auth_cookie();

        $logoutUrl = self::endSessionUrl(add_query_arg('jwt_auth_denied', '1', home_url('/')));
        if ($logoutUrl !== null) {
            wp_redirect($logoutUrl);
            exit;
        }

        Registration::deny();
    }

    /** Renders the notice after the provider bounces a denied sign-in back to us. */
    public static function handleDeniedReturn(): void
    {
        if (($_GET['jwt_auth_denied'] ?? '') !== '1') return;

        // The refused visitor arrives here signed out, since denyRegistration() cleared the cookie
        // before the bounce. Anyone reaching this URL with a session is a member following a stale
        // link, and telling them the site is closed to new accounts would only confuse them.
        if (is_user_logged_in()) return;

        Registration::deny();
    }

    // -------------------------------------------------------------------------
    // wp_logout hook
    // -------------------------------------------------------------------------

    public static function handleLogout(): void
    {
        // A configured JWT_AUTH_LOGOUT_URL is used verbatim: it may already carry the query string
        // the provider expects, and appending a post_logout_redirect_uri the provider has not
        // registered turns a working sign-out into an error page.
        $logoutUrl = Config::logoutUrl() ?? self::endSessionUrl(home_url('/'));

        if ($logoutUrl !== null) {
            wp_redirect($logoutUrl);
            exit;
        }
    }

    /** Discovered end-session URL returning the browser to $returnTo, or null if there is none. */
    private static function endSessionUrl(string $returnTo): ?string
    {
        if (Config::issuer() === '') return null;

        $endpoint = self::tryDiscover()['end_session_endpoint'] ?? null;
        if (!is_string($endpoint) || $endpoint === '') return null;

        return $endpoint . '?' . http_build_query([
            'post_logout_redirect_uri' => $returnTo,
        ]);
    }

    // -------------------------------------------------------------------------
    // PKCE + state helpers
    // -------------------------------------------------------------------------

    /**
     * Mint the CSRF state, and bind it to THIS browser.
     *
     * WordPress transients are site-global: a state minted in one browser is redeemable in any
     * other. On its own that makes `state` a shared server-side nonce rather than the per-user-agent
     * value RFC 6749 §10.12 requires, and it makes PKCE inert here too — the same unbound transient
     * hands out the verifier, so whoever minted the pair is not necessarily whoever redeems it.
     *
     * The consequence is authorization-code injection: an attacker completes a sign-in as
     * themselves, holds the resulting code, and navigates a victim to the callback. Every check
     * passes on the merits, the victim's own session is destroyed, and they are silently logged in
     * as the attacker — on a landing page the attacker also chose, since redirect_to travels inside
     * the state transient.
     *
     * The fix is a secret this browser holds and the transient only knows the hash of, so a
     * callback arriving in any other browser cannot satisfy it.
     */
    private static function generateState(string $redirectTo): string
    {
        $state  = bin2hex(random_bytes(16));
        $binder = bin2hex(random_bytes(32));

        set_transient(self::STATE_PREFIX . $state, [
            'redirect_to' => $redirectTo ?: Config::redirect(),
            'binder'      => hash('sha256', $binder),
        ], self::TRANSIENT_TTL);

        setcookie(self::STATE_COOKIE, $binder, [
            'expires'  => time() + self::TRANSIENT_TTL,
            'path'     => '/',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        return $state;
    }

    /** Clear the binder on every callback outcome, so a state can never be retried. */
    private static function clearStateCookie(): void
    {
        setcookie(self::STATE_COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private static function generatePkce(string $state): string
    {
        $verifier  = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, binary: true)), '+/', '-_'), '=');
        set_transient(self::VERIFIER_PREFIX . $state, $verifier, self::TRANSIENT_TTL);
        return $challenge;
    }

    /** @return array<string, mixed> */
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

    /**
     * Silent discovery attempt — returns empty array on failure (used for optional features like logout).
     *
     * @return array<string, mixed>
     */
    private static function tryDiscover(): array
    {
        try {
            return self::discover();
        } catch (\Throwable) {
            return [];
        }
    }
}
