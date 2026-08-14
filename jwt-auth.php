<?php

/**
 * Plugin Name:       JWT Auth
 * Description:       Redirect all WordPress authentication to an external OIDC or proxy JWT provider. Configure via wp-config.php — no admin UI required.
 * x-release-please-start-version
 * Version:           4.1.0
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
 * Neither whether accounts are created nor what they can do is a constant — both follow
 * WordPress's own Settings > General:
 *
 *   Membership > "Anyone can register"  — untick it and the provider can authenticate
 *     whoever it likes without a WordPress account being minted. WordPress ships it unticked.
 *   "New User Default Role"             — the role a newly provisioned account receives,
 *     exactly as for any other registration path on the site.
 *
 *   define('JWT_AUTH_CLAIM_EMAIL',      'email');
 *   define('JWT_AUTH_CLAIM_FIRST_NAME', 'given_name');
 *   define('JWT_AUTH_CLAIM_LAST_NAME',  'family_name');
 *   define('JWT_AUTH_CLAIM_NAME',       'name');
 *
 * --- UX ----------------------------------------------------------------------
 *   define('JWT_AUTH_REDIRECT',       '/');    // post-login destination
 *   define('JWT_AUTH_PROVIDER_NAME',  'SSO');  // WooCommerce button label
 *
 *   define('JWT_AUTH_EXCLUSIVE',      true);   // remove native password forms entirely
 *
 * JWT_AUTH_EXCLUSIVE makes the provider the only offer on the page rather than one of two. Without
 * it, credentials are refused but the forms remain: WordPress's login block and wp_login_form(),
 * WooCommerce's My Account and checkout forms, and "Lost your password?" all still render fields
 * nothing can accept. With it, those are replaced by the sign-in button, and the WooCommerce flows
 * that hand out a session *without* passing through the `authenticate` filter — password reset and
 * registration, both of which call wc_set_customer_auth_cookie() — are closed. See ExclusiveLogin
 * and the README for the full list of what it turns off.
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

use JwtAuth\{AuthMode, Config, ExclusiveLogin, OidcClient, UserManager, Validator, WooCommerce};

add_action('plugins_loaded', static function (): void {
    try {
        $mode = Config::detectMode();
    } catch (\RuntimeException) {
        // Plugin not configured — do nothing so WordPress remains functional.
        return;
    }

    // Check for OIDC callback on every early init (priority 1, before anything else reads the request).
    add_action('init', OidcClient::handleCallback(...), 1);

    // Explain a refused sign-in once the provider has bounced the browser back to us.
    add_action('init', OidcClient::handleDeniedReturn(...), 1);

    // Block all direct username/password authentication attempts.
    //
    // Priority 30 is load-bearing: `authenticate` is a filter, so the login is decided by whatever
    // the LAST callback returns, and core registers wp_authenticate_username_password,
    // wp_authenticate_email_password and wp_authenticate_application_password at priority 20. At
    // priority 1 this refusal was simply overwritten by core's WP_User on every path that does not
    // go through wp-login.php — XML-RPC and application passwords among them. Run after core, and
    // below wp_authenticate_spam_check at 99.
    add_filter('authenticate', Validator::blockDirectAuth(...), 30, 3);

    if ($mode === AuthMode::Proxy) {
        // Validate the proxy-injected JWT on every unauthenticated request.
        add_action('init', Validator::validateProxyJwt(...), 5);
    } else {
        // Intercept wp-login.php and redirect to the OIDC provider.
        add_action('login_init', OidcClient::redirectToProvider(...));
    }

    // An administrator changing a user's email must actually revoke the old address, rather than
    // leaving it authoritative through a provider binding that outlives it.
    add_action('profile_update', UserManager::forgetSubOnEmailChange(...), 10, 2);

    // Handle logout — redirect to provider end-session endpoint when available.
    add_action('wp_logout', OidcClient::handleLogout(...));

    // WooCommerce sign-in block / form override (OIDC mode only).
    if (class_exists('WooCommerce')) {
        add_action('woocommerce_login_form_start', WooCommerce::renderSsoButton(...));
        add_action('wp_enqueue_scripts', WooCommerce::enqueueAssets(...));
    }

    // JWT_AUTH_EXCLUSIVE: replace the native password forms instead of standing beside them.
    //
    // `plugins_loaded` is load-bearing for the WooCommerce half: it calls remove_action() on
    // WC_Form_Handler's hooks, and those are attached while WooCommerce's plugin file is being
    // included — earlier than any hook — so by now they exist to be removed. Moving this to `init`
    // would also work; moving it to plugin-load time would not.
    if (Config::exclusive()) {
        ExclusiveLogin::register();
    }
});
