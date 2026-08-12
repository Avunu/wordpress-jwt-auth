<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use Firebase\JWT\JWT;
use JwtAuth\Tests\Support\KeyFixture;
use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpState;
use JwtAuth\Validator;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * The security boundary. Everything downstream — which WordPress account you get, whether you are
 * logged in at all — follows from decode() accepting a token, so most of these are negative: a
 * forged, expired, or wrongly-signed token must not get through.
 */
#[CoversClass(Validator::class)]
final class ValidatorTest extends WordPressTestCase
{
    public function test_decodes_a_genuinely_signed_token(): void
    {
        $key = KeyFixture::primary();
        $this->registerJwks($key);

        $claims = Validator::decode($key->sign(), self::JWKS_URI);

        $this->assertSame('user@example.test', $claims->email);
        $this->assertSame('pin:abc123', $claims->sub);
        $this->assertSame(self::ISSUER, $claims->iss);
        $this->assertTrue($claims->hasAudience(self::CLIENT_ID));
    }

    public function test_rejects_an_unsigned_alg_none_token(): void
    {
        // The oldest JWT forgery there is: strip the signature and declare the token unsigned.
        $key = KeyFixture::primary();
        $this->registerJwks($key);

        $this->expectException(\UnexpectedValueException::class);
        Validator::decode($key->unsignedNoneToken(), self::JWKS_URI);
    }

    public function test_rejects_an_hmac_token_forged_with_the_public_key(): void
    {
        // Algorithm confusion: sign with HS256 using the RSA public key as the shared secret. A
        // verifier that trusts the token's own `alg` header accepts it, because the "secret" is
        // published in the JWKS for anyone to read.
        $key = KeyFixture::primary();
        $this->registerJwks($key);

        $this->expectException(\UnexpectedValueException::class);
        Validator::decode($key->hmacForgedToken(), self::JWKS_URI);
    }

    public function test_rejects_a_token_signed_by_a_key_that_is_not_published(): void
    {
        // The rotated key is a real RSA key — just not one this issuer advertises.
        $this->registerJwks(KeyFixture::primary());

        $this->expectException(\UnexpectedValueException::class);
        Validator::decode(KeyFixture::rotated()->sign(), self::JWKS_URI);
    }

    public function test_rejects_a_token_whose_signature_does_not_match_its_payload(): void
    {
        $key = KeyFixture::primary();
        $this->registerJwks($key);

        // Tamper with the payload, keeping the original signature.
        [$header, $payload, $signature] = explode('.', $key->sign());
        $decoded = json_decode(JWT::urlsafeB64Decode($payload), true);
        $decoded['email'] = 'attacker@evil.test';
        $tampered = $header . '.' . JWT::urlsafeB64Encode((string) json_encode($decoded)) . '.' . $signature;

        $this->expectException(\Throwable::class);
        Validator::decode($tampered, self::JWKS_URI);
    }

    public function test_rejects_an_expired_token_but_allows_the_leeway_window(): void
    {
        $key = KeyFixture::primary();
        $this->registerJwks($key);
        $now = time();

        // 30s past expiry is inside the 60s leeway that absorbs clock skew.
        $claims = Validator::decode($key->sign(['exp' => $now - 30]), self::JWKS_URI);
        $this->assertSame('user@example.test', $claims->email);

        $this->expectException(\Firebase\JWT\ExpiredException::class);
        Validator::decode($key->sign(['exp' => $now - 3600]), self::JWKS_URI);
    }

    public function test_rejects_a_token_that_is_not_yet_valid(): void
    {
        $key = KeyFixture::primary();
        $this->registerJwks($key);

        $this->expectException(\Firebase\JWT\BeforeValidException::class);
        Validator::decode($key->sign(['nbf' => time() + 3600]), self::JWKS_URI);
    }

    public function test_refetches_the_jwks_once_when_the_signing_key_has_rotated(): void
    {
        // The realistic rotation case: our cache holds yesterday's key, the issuer has moved on.
        // One transparent refresh must rescue the login rather than failing it.
        $old = KeyFixture::primary();
        $new = KeyFixture::rotated();

        WpState::$transients['jwt_auth_jwks_' . md5(self::JWKS_URI)] = KeyFixture::jwks([$old]);
        WpState::respondJson(self::JWKS_URI, KeyFixture::jwks([$old, $new]));

        $claims = Validator::decode($new->sign(), self::JWKS_URI);

        $this->assertSame('user@example.test', $claims->email);
        $this->assertCount(1, WpState::$httpCalls, 'exactly one refresh, not a retry storm');
        $this->assertSame(self::JWKS_URI, WpState::$httpCalls[0]['url']);
    }

    public function test_gives_up_after_a_single_refresh(): void
    {
        // A key that is genuinely unknown must not send us fetching in a loop.
        $this->registerJwks(KeyFixture::primary());

        try {
            Validator::decode(KeyFixture::rotated()->sign(), self::JWKS_URI);
            $this->fail('expected the unknown key to be rejected');
        } catch (\Throwable) {
            // expected
        }

        $this->assertLessThanOrEqual(2, count(WpState::$httpCalls));
    }

    public function test_an_expired_token_currently_costs_a_redundant_jwks_refetch(): void
    {
        // Documents present behaviour, not desired behaviour. decode() treats any
        // UnexpectedValueException as "the keys may have rotated" and refetches once — but
        // ExpiredException and BeforeValidException both extend UnexpectedValueException, so an
        // ordinary expired token also pays for a refetch.
        //
        // In OIDC mode that is merely wasteful (it happens once, at the callback). In proxy mode
        // validateProxyJwt() runs on every unauthenticated request carrying a token, so replaying
        // one expired token forces an outbound HTTPS request per hit.
        //
        // Narrowing the catch is not a one-liner: a genuinely rotated key usually surfaces as a
        // *kid lookup* failure, which is a plain UnexpectedValueException too, so the retry cannot
        // simply be restricted to SignatureInvalidException without breaking rotation.
        $key = KeyFixture::primary();
        $this->registerJwks($key);

        try {
            Validator::decode($key->sign(['exp' => time() - 3600]), self::JWKS_URI);
        } catch (\Firebase\JWT\ExpiredException) {
            // expected
        }

        $this->assertCount(2, WpState::$httpCalls, 'change this to 1 when the catch is narrowed');
    }

    public function test_blocks_direct_username_and_password_login(): void
    {
        $result = Validator::blockDirectAuth(null, 'admin', 'hunter2');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('jwt_auth_required', $result->get_error_code());
        $this->assertStringContainsString('Direct login is disabled', $result->get_error_message());
        // The default provider label, since JWT_AUTH_PROVIDER_NAME is left undefined.
        $this->assertStringContainsString('SSO', $result->get_error_message());
    }

    public function test_allows_direct_auth_during_cron_so_scheduled_tasks_keep_working(): void
    {
        // wp_authenticate() seeds the `authenticate` filter with null, so null is the value this
        // hook is overwhelmingly called with — including under cron and WP-CLI, where the plugin
        // is supposed to step aside rather than block.
        WpState::$doingCron = true;

        $this->assertNull(Validator::blockDirectAuth(null, 'admin', 'hunter2'));
    }

    public function test_passes_an_already_authenticated_user_straight_through_during_cron(): void
    {
        WpState::$doingCron = true;
        $user = WpState::addUser('cron@example.test');

        $this->assertSame($user, Validator::blockDirectAuth($user, 'cron', 'hunter2'));
    }

    public function test_proxy_mode_refuses_to_run_without_an_explicit_jwks_uri(): void
    {
        // Proxy mode cannot discover its own JWKS, so a missing constant must fail loudly rather
        // than silently leaving every request unauthenticated.
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . KeyFixture::primary()->sign();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('JWT_AUTH_JWKS_URI must be defined');
        Validator::validateProxyJwt();
    }

    public function test_proxy_mode_ignores_requests_that_carry_no_token(): void
    {
        Validator::validateProxyJwt();

        $this->assertSame([], WpState::$authCookies);
        $this->assertSame([], WpState::$httpCalls);
    }
}
