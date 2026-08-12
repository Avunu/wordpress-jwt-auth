<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\Jwks;
use JwtAuth\Tests\Support\KeyFixture;
use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpState;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Jwks::class)]
final class JwksTest extends WordPressTestCase
{
    public function test_fetches_on_a_cache_miss_and_serves_from_cache_afterwards(): void
    {
        // Every login validates a signature, so an uncached JWKS would mean an outbound request
        // per sign-in.
        $this->registerJwks(KeyFixture::primary());

        $first = Jwks::get(self::JWKS_URI);
        $second = Jwks::get(self::JWKS_URI);

        $this->assertSame($first, $second);
        $this->assertCount(1, WpState::$httpCalls);
    }

    public function test_refresh_bypasses_the_cache_and_replaces_it(): void
    {
        $old = KeyFixture::primary();
        $new = KeyFixture::rotated();
        WpState::$transients['jwt_auth_jwks_' . md5(self::JWKS_URI)] = KeyFixture::jwks([$old]);
        WpState::respondJson(self::JWKS_URI, KeyFixture::jwks([$new]));

        $refreshed = Jwks::refresh(self::JWKS_URI);

        $this->assertSame($new->kid, $refreshed['keys'][0]['kid']);
        // The new set is now what a subsequent get() serves, without another fetch.
        $this->assertSame($refreshed, Jwks::get(self::JWKS_URI));
        $this->assertCount(1, WpState::$httpCalls);
    }

    public function test_caches_per_uri_so_two_issuers_never_share_a_key_set(): void
    {
        $other = 'https://other.test/.well-known/jwks.json';
        $this->registerJwks(KeyFixture::primary());
        WpState::respondJson($other, KeyFixture::jwks([KeyFixture::rotated()]));

        $this->assertSame(KeyFixture::primary()->kid, Jwks::get(self::JWKS_URI)['keys'][0]['kid']);
        $this->assertSame(KeyFixture::rotated()->kid, Jwks::get($other)['keys'][0]['kid']);
    }

    public function test_throws_when_the_endpoint_is_unreachable(): void
    {
        // No response registered, so the fake returns a WP_Error like a real network failure.
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('JWKS fetch failed');

        Jwks::refresh(self::JWKS_URI);
    }

    public function test_throws_on_a_response_with_no_keys(): void
    {
        // A 200 with an error body, or an HTML captive-portal page, must not be cached as a valid
        // empty key set — that would fail every login for an hour.
        WpState::respondJson(self::JWKS_URI, ['keys' => []]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid JWKS response');

        Jwks::refresh(self::JWKS_URI);
    }

    public function test_does_not_cache_a_failed_fetch(): void
    {
        WpState::respondJson(self::JWKS_URI, ['keys' => []]);

        try {
            Jwks::refresh(self::JWKS_URI);
        } catch (\RuntimeException) {
            // expected
        }

        $this->assertSame([], WpState::$transients);
    }
}
