<?php

/**
 * Plugin Name:       JWT Auth
 * Description:       Redirect all WordPress authentication to an external OIDC or proxy JWT provider. Configure via wp-config.php — no admin UI required.
 * x-release-please-start-version
 * Version:           1.1.0
 * x-release-please-end
 * Requires PHP:      8.4
 * License:           MIT
 *
 * ============================================================================
 * CONFIGURATION (wp-config.php)
 * ============================================================================
 *
 * --- OIDC mode (Zitadel, Keycloak, Auth0, …) --------------------------------
 * Activated when JWT_AUTH_CLIENT_ID is defined.
 * Endpoints are auto-discovered from {issuer}/.well-known/openid-configuration.
 *
 *   define('JWT_AUTH_ISSUER',        'https://your.zitadel.cloud');
 *   define('JWT_AUTH_CLIENT_ID',     'your-client-id@project');
 *   define('JWT_AUTH_CLIENT_SECRET', '');   // empty = PKCE-only (recommended)
 *
 * --- Proxy mode (Cloudflare Zero Trust, Authentik, Traefik, …) --------------
 * Activated when JWT_AUTH_CLIENT_ID is absent and JWT_AUTH_JWKS_URI is set.
 * The upstream proxy must inject a signed JWT into every authenticated request.
 *
 *   // Cloudflare Zero Trust example:
 *   define('JWT_AUTH_ISSUER',       'https://yourteam.cloudflareaccess.com');
 *   define('JWT_AUTH_JWKS_URI',     'https://yourteam.cloudflareaccess.com/cdn-cgi/access/certs');
 *   define('JWT_AUTH_AUD',          'your-cf-audience-tag');
 *   define('JWT_AUTH_TOKEN_COOKIE', 'CF_Authorization');
 *   // define('JWT_AUTH_TOKEN_HEADER', 'Cf-Access-Jwt-Assertion'); // OR a header name
 *
 * --- Overrides (work in either mode) ----------------------------------------
 *   define('JWT_AUTH_JWKS_URI',     '...');  // override OIDC-discovered JWKS URI
 *   define('JWT_AUTH_AUD',          '...');  // override audience claim check
 *   define('JWT_AUTH_LOGOUT_URL',   '...');  // provider logout URL (optional)
 *
 * --- User creation -----------------------------------------------------------
 *   define('JWT_AUTH_DEFAULT_ROLE',     'subscriber');  // default
 *   define('JWT_AUTH_CLAIM_EMAIL',      'email');
 *   define('JWT_AUTH_CLAIM_FIRST_NAME', 'given_name');
 *   define('JWT_AUTH_CLAIM_LAST_NAME',  'family_name');
 *   define('JWT_AUTH_CLAIM_NAME',       'name');
 *
 * --- UX ----------------------------------------------------------------------
 *   define('JWT_AUTH_REDIRECT',       '/');    // post-login destination
 *   define('JWT_AUTH_PROVIDER_NAME',  'SSO');  // WooCommerce button label
 */

declare(strict_types=1);

defined('WPINC') || exit;

require_once __DIR__ . '/vendor/autoload.php';

// Self-update from GitHub releases. The built zip attached to each release bundles
// vendor/, so end users never need Composer.
require_once __DIR__ . '/vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php';

$jwtAuthUpdateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
    'https://github.com/Avunu/wordpress-jwt-auth/',
    __FILE__,
    'jwt-auth'
);
$jwtAuthVcsApi = $jwtAuthUpdateChecker->getVcsApi();
// Download the built release asset, not GitHub's source tarball (which lacks vendor/).
$jwtAuthVcsApi->enableReleaseAssets('/jwt-auth\.zip$/');
// This repo also publishes the companion worker under `jwt-auth-worker-v*` tags. Only
// consider plain version tags (v1.2.3) so those never masquerade as a plugin update. PUC
// derives the version as ltrim(tag, 'v'), so the filter matches a bare version number.
$jwtAuthVcsApi->setReleaseVersionFilter('/^\d+\.\d+\.\d+/');

use JwtAuth\{AuthMode, Config, OidcClient, Validator, WooCommerce};

add_action('plugins_loaded', static function (): void {
    try {
        $mode = Config::detectMode();
    } catch (\RuntimeException) {
        // Plugin not configured — do nothing so WordPress remains functional.
        return;
    }

    // Check for OIDC callback on every early init (priority 1, before anything else reads the request).
    add_action('init', OidcClient::handleCallback(...), 1);

    // Block all direct username/password authentication attempts.
    add_filter('authenticate', Validator::blockDirectAuth(...), 1, 3);

    if ($mode === AuthMode::Proxy) {
        // Validate the proxy-injected JWT on every unauthenticated request.
        add_action('init', Validator::validateProxyJwt(...), 5);
    } else {
        // Intercept wp-login.php and redirect to the OIDC provider.
        add_action('login_init', OidcClient::redirectToProvider(...));
    }

    // Handle logout — redirect to provider end-session endpoint when available.
    add_action('wp_logout', OidcClient::handleLogout(...));

    // WooCommerce sign-in block / form override (OIDC mode only).
    if (class_exists('WooCommerce')) {
        add_action('woocommerce_login_form_start', WooCommerce::renderSsoButton(...));
        add_action('wp_enqueue_scripts', WooCommerce::enqueueAssets(...));
    }
});
