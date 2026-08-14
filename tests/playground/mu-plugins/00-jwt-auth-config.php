<?php

/**
 * Test-only. Defines the wp-config.php constants the plugin reads, so Config::detectMode() returns
 * AuthMode::Oidc inside wp-playground and the WooCommerce hooks are registered. Loaded as an
 * mu-plugin — before plugins_loaded, where jwt-auth.php reads them.
 *
 * The issuer is never contacted by anything these tests exercise: rendering the button calls only
 * Config::detectMode() and wp_login_url(), and OIDC discovery happens on the wp-login.php redirect,
 * which no assertion here follows. It is set to an unroutable host so that a future test that does
 * reach for the network fails loudly rather than silently talking to a real provider.
 */

declare(strict_types=1);

defined('JWT_AUTH_ISSUER')        || define('JWT_AUTH_ISSUER', 'https://oidc.invalid');
defined('JWT_AUTH_CLIENT_ID')     || define('JWT_AUTH_CLIENT_ID', 'playground-test');
defined('JWT_AUTH_CLIENT_SECRET') || define('JWT_AUTH_CLIENT_SECRET', '');
defined('JWT_AUTH_PROVIDER_NAME') || define('JWT_AUTH_PROVIDER_NAME', 'SSO');
