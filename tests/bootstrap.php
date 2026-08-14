<?php

declare(strict_types=1);

// PHPUnit bootstrap. Loads the plugin's own autoloader, then the fake WordPress the plugin runs
// against, then defines the wp-config.php constants the suite exercises.
//
// Constants are process-global and cannot be redefined, so the set below is fixed for the whole
// run and chosen to maximise what a single process can cover: JWT_AUTH_CLIENT_ID selects OIDC mode
// (the mode the fleet actually deploys), while everything optional is deliberately left undefined
// so Config's defaults are exercised rather than assumed.

require_once __DIR__ . '/../vendor/autoload.php';
// Global-scope function definitions cannot be autoloaded; everything else in Support/ is PSR-4.
require_once __DIR__ . '/Support/functions.php';
require_once __DIR__ . '/Support/namespaced.php';

define('JWT_AUTH_ISSUER', 'https://auth.test');
define('JWT_AUTH_CLIENT_ID', 'testclient');

// Intentionally NOT defined, so the suite covers the fallback paths:
//   JWT_AUTH_CLIENT_SECRET  -> '' (PKCE-only public client)
//   JWT_AUTH_JWKS_URI       -> null (JWKS discovered, and proxy mode refuses to run)
//   JWT_AUTH_AUD            -> null (audience falls back to client_id)
//   JWT_AUTH_DEFAULT_ROLE   -> 'subscriber'
//   JWT_AUTH_CLAIM_*        -> standard OIDC claim names
//   JWT_AUTH_REDIRECT       -> '/'
//   JWT_AUTH_PROVIDER_NAME  -> 'SSO'
//   JWT_AUTH_LOGOUT_URL     -> null (end_session_endpoint from discovery)
//
// One consequence worth naming: leaving JWT_AUTH_LOGOUT_URL undefined means the "Sign out of
// {Provider}" link Registration::deny() appends when it *is* defined goes uncovered. Defining it
// here to reach that branch would change what handleLogout() does in every other test, which is a
// worse trade than the gap.
