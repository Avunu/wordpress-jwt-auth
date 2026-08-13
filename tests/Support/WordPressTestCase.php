<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Support;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

/** Base case: a clean in-memory WordPress for every test, and a frozen clock for JWT expiry. */
abstract class WordPressTestCase extends TestCase
{
    protected const ISSUER = 'https://auth.test';
    protected const CLIENT_ID = 'testclient';
    protected const JWKS_URI = 'https://auth.test/.well-known/jwks.json';
    protected const CALLBACK = 'https://example.test/?jwt_auth_callback=1';

    protected function setUp(): void
    {
        parent::setUp();
        WpState::reset();
        JWT::$timestamp = null;
        $_GET = [];
        $_REQUEST = [];
        $_SERVER = ['HTTP_HOST' => 'example.test'];
        $_COOKIE = [];
        // wp-includes/vars.php sets this during bootstrap, long before the init hooks under test.
        $GLOBALS['pagenow'] = 'index.php';
    }

    protected function tearDown(): void
    {
        JWT::$timestamp = null;
        parent::tearDown();
    }

    /** Register the OIDC discovery document the plugin fetches on first use. */
    protected function registerDiscovery(array $overrides = []): void
    {
        WpState::respondJson(self::ISSUER . '/.well-known/openid-configuration', array_merge([
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint' => self::ISSUER . '/token',
            'jwks_uri' => self::JWKS_URI,
            'end_session_endpoint' => self::ISSUER . '/logout',
        ], $overrides));
    }

    /** Publish a JWKS containing the given keys at the discovery-advertised URI. */
    protected function registerJwks(KeyFixture ...$keys): void
    {
        WpState::respondJson(self::JWKS_URI, KeyFixture::jwks($keys));
    }
}
