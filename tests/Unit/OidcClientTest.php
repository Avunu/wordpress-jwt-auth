<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\OidcClient;
use JwtAuth\Tests\Support\KeyFixture;
use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpDieException;
use JwtAuth\Tests\Support\WpRedirectException;
use JwtAuth\Tests\Support\WpState;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * The redirect flow end to end. The security-relevant properties here are that `state` is
 * unguessable and single-use, that the PKCE verifier never leaves the server, and that a token is
 * refused unless both its issuer and its audience are the ones this site expects.
 */
#[CoversClass(OidcClient::class)]
final class OidcClientTest extends WordPressTestCase
{
    private const TOKEN_ENDPOINT = self::ISSUER . '/token';

    protected function setUp(): void
    {
        parent::setUp();
        $this->registerDiscovery();
        $this->registerJwks(KeyFixture::primary());
    }

    /** Drive the authorize redirect and return its query parameters. */
    private function startLogin(): array
    {
        try {
            OidcClient::redirectToProvider();
            $this->fail('expected a redirect to the provider');
        } catch (WpRedirectException $redirect) {
            return $redirect->query();
        }
    }

    /** Register the token endpoint's response for a given id_token. */
    private function registerTokenResponse(string $idToken): void
    {
        WpState::respondJson(self::TOKEN_ENDPOINT, ['id_token' => $idToken, 'token_type' => 'Bearer']);
    }

    // ---------------------------------------------------------------------
    // Authorization request
    // ---------------------------------------------------------------------

    public function test_redirects_to_the_provider_with_a_complete_pkce_request(): void
    {
        $params = $this->startLogin();

        $this->assertSame('code', $params['response_type']);
        $this->assertSame(self::CLIENT_ID, $params['client_id']);
        $this->assertSame(self::CALLBACK, $params['redirect_uri']);
        $this->assertSame('openid email profile', $params['scope']);
        $this->assertSame('S256', $params['code_challenge_method']);
        $this->assertNotEmpty($params['state']);
    }

    public function test_the_code_challenge_is_the_s256_hash_of_the_stored_verifier(): void
    {
        // The verifier stays in a transient and never travels through the browser; only its hash
        // does. Getting this wrong would silently disable PKCE.
        $params = $this->startLogin();

        $verifier = WpState::$transients['jwt_auth_cv_' . $params['state']];
        $expected = rtrim(strtr(base64_encode(hash('sha256', $verifier, binary: true)), '+/', '-_'), '=');

        $this->assertSame($expected, $params['code_challenge']);
        $this->assertStringNotContainsString($verifier, http_build_query($params));
    }

    public function test_state_is_unguessable_and_unique_per_attempt(): void
    {
        $first = $this->startLogin()['state'];
        $second = $this->startLogin()['state'];

        $this->assertNotSame($first, $second);
        $this->assertSame(32, strlen($first), '128 bits of entropy, hex encoded');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $first);
    }

    public function test_remembers_where_the_user_was_going(): void
    {
        $_REQUEST['redirect_to'] = 'https://example.test/members/';

        $params = $this->startLogin();

        $this->assertSame(
            'https://example.test/members/',
            WpState::$transients['jwt_auth_state_' . $params['state']]['redirect_to'],
        );
    }

    // ---------------------------------------------------------------------
    // The state must belong to the browser that started the flow
    // ---------------------------------------------------------------------

    public function test_the_state_transient_stores_only_a_hash_of_the_browser_secret(): void
    {
        // WordPress transients are site-global and readable by anything with database access, so
        // the secret itself must not live there — only something the cookie can be checked against.
        $params = $this->startLogin();
        $record = WpState::$transients['jwt_auth_state_' . $params['state']];
        $binder = $_COOKIE['jwt_auth_state_binder'];

        $this->assertNotSame($binder, $record['binder']);
        $this->assertSame(hash('sha256', $binder), $record['binder']);
    }

    public function test_the_binder_cookie_is_not_readable_or_sendable_by_a_third_party(): void
    {
        $this->startLogin();
        $cookie = end(WpState::$cookiesSet);

        $this->assertSame('jwt_auth_state_binder', $cookie['name']);
        $this->assertTrue($cookie['options']['httponly'], 'script must not be able to read it');
        $this->assertTrue($cookie['options']['secure']);
        $this->assertSame('Lax', $cookie['options']['samesite']);
        // Outliving the transient would leave a usable binder for a state that no longer exists.
        $this->assertLessThanOrEqual(time() + 600, $cookie['options']['expires']);
    }

    public function test_rejects_a_callback_arriving_in_a_different_browser(): void
    {
        // Authorization-code injection. The attacker completes a real sign-in as themselves, holds
        // the code, and navigates the victim to the callback. Every other check passes on the
        // merits — the transient exists, the code is valid, the token verifies — so without a
        // browser binding the victim is silently logged in as the attacker.
        $params = $this->startLogin();
        $this->registerTokenResponse(KeyFixture::primary()->sign());
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        unset($_COOKIE['jwt_auth_state_binder']); // the victim's browser never saw it

        try {
            OidcClient::handleCallback();
            $this->fail('expected the callback to be refused');
        } catch (WpDieException $died) {
            $this->assertStringContainsString('Invalid or expired authentication state', $died->body);
            $this->assertSame(400, $died->status());
        }

        $this->assertSame([], WpState::$authCookies, 'no session may be established');
        $this->assertFalse(WpState::$authCookieCleared, "and the victim's own session survives");
    }

    public function test_rejects_a_callback_carrying_the_wrong_browser_secret(): void
    {
        $params = $this->startLogin();
        $this->registerTokenResponse(KeyFixture::primary()->sign());
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        $_COOKIE['jwt_auth_state_binder'] = bin2hex(random_bytes(32)); // a binder from another flow

        $this->expectException(WpDieException::class);
        $this->expectExceptionMessage('Invalid or expired authentication state');
        OidcClient::handleCallback();
    }

    public function test_a_refused_callback_consumes_the_state_and_the_verifier(): void
    {
        // Otherwise the attacker simply retries against the next victim with the same pair.
        $params = $this->startLogin();
        $this->registerTokenResponse(KeyFixture::primary()->sign());
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];
        unset($_COOKIE['jwt_auth_state_binder']);

        try {
            OidcClient::handleCallback();
        } catch (WpDieException) {
            // expected
        }

        $this->assertArrayNotHasKey('jwt_auth_state_' . $params['state'], WpState::$transients);
        $this->assertArrayNotHasKey('jwt_auth_cv_' . $params['state'], WpState::$transients);
    }

    public function test_the_binder_is_cleared_after_a_successful_login(): void
    {
        $this->completeLogin();

        $this->assertArrayNotHasKey('jwt_auth_state_binder', $_COOKIE);
    }

    public function test_stands_aside_for_wordpress_own_logout(): void
    {
        // Redirecting here would bounce the user to the sign-in screen with their WordPress session
        // still intact, because wp_logout() would never run.
        $_REQUEST['action'] = 'logout';

        OidcClient::redirectToProvider();

        $this->assertSame([], WpState::$authCookies);
        $this->addToAssertionCount(1);
    }

    // ---------------------------------------------------------------------
    // Callback
    // ---------------------------------------------------------------------

    /** Complete a full login and return the redirect the browser is finally sent to. */
    private function completeLogin(?string $idToken = null): WpRedirectException
    {
        $params = $this->startLogin();
        $this->registerTokenResponse($idToken ?? KeyFixture::primary()->sign());

        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        try {
            OidcClient::handleCallback();
            $this->fail('expected a redirect after a successful login');
        } catch (WpRedirectException $redirect) {
            return $redirect;
        }
    }

    public function test_a_valid_callback_logs_the_user_in_and_returns_them_to_the_site(): void
    {
        $_REQUEST['redirect_to'] = 'https://example.test/members/';

        $redirect = $this->completeLogin();

        $this->assertTrue($redirect->safe, 'the final hop must go through wp_safe_redirect');
        $this->assertSame('https://example.test/members/', $redirect->location);

        $this->assertCount(1, WpState::$authCookies);
        $this->assertTrue(WpState::$authCookies[0]['remember']);
        $this->assertTrue(WpState::$authCookieCleared, 'any prior session must be cleared first');
        $this->assertSame('wp_login', WpState::$actions[0]['hook'] ?? null);

        $user = WpState::$users[WpState::$authCookies[0]['id']];
        $this->assertSame('user@example.test', $user->user_email);
    }

    public function test_ignores_requests_that_are_not_the_callback(): void
    {
        $_GET = [];
        OidcClient::handleCallback();

        $this->assertSame([], WpState::$authCookies);
        $this->addToAssertionCount(1);
    }

    public function test_rejects_a_callback_with_missing_parameters(): void
    {
        $_GET = ['jwt_auth_callback' => '1', 'state' => 'abc'];

        $this->expectException(WpDieException::class);
        $this->expectExceptionMessage('Missing callback parameters');
        OidcClient::handleCallback();
    }

    public function test_rejects_an_unknown_state(): void
    {
        // The CSRF gate: a state we never issued means this callback did not start here.
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => 'never-issued'];

        try {
            OidcClient::handleCallback();
            $this->fail('expected the callback to be refused');
        } catch (WpDieException $died) {
            $this->assertStringContainsString('Invalid or expired authentication state', $died->body);
            $this->assertSame(400, $died->status());
        }
        $this->assertSame([], WpState::$authCookies);
    }

    public function test_state_is_single_use(): void
    {
        // Replaying a captured callback URL must not produce a second session.
        $params = $this->startLogin();
        $this->registerTokenResponse(KeyFixture::primary()->sign());
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        try {
            OidcClient::handleCallback();
        } catch (WpRedirectException) {
            // first use succeeds
        }
        $this->assertCount(1, WpState::$authCookies);

        $this->expectException(WpDieException::class);
        $this->expectExceptionMessage('Invalid or expired authentication state');
        OidcClient::handleCallback();
    }

    public function test_consumes_the_pkce_verifier_too(): void
    {
        $params = $this->startLogin();
        $this->registerTokenResponse(KeyFixture::primary()->sign());
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        try {
            OidcClient::handleCallback();
        } catch (WpRedirectException) {
            // expected
        }

        $this->assertArrayNotHasKey('jwt_auth_cv_' . $params['state'], WpState::$transients);
        $this->assertArrayNotHasKey('jwt_auth_state_' . $params['state'], WpState::$transients);
    }

    public function test_sends_the_verifier_not_the_challenge_when_redeeming_the_code(): void
    {
        $params = $this->startLogin();
        $verifier = WpState::$transients['jwt_auth_cv_' . $params['state']];
        $this->registerTokenResponse(KeyFixture::primary()->sign());
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        try {
            OidcClient::handleCallback();
        } catch (WpRedirectException) {
            // expected
        }

        $tokenCall = null;
        foreach (WpState::$httpCalls as $call) {
            if ($call['url'] === self::TOKEN_ENDPOINT) {
                $tokenCall = $call;
            }
        }
        $this->assertNotNull($tokenCall, 'the code should have been redeemed');
        $this->assertSame('POST', $tokenCall['method']);
        $this->assertSame($verifier, $tokenCall['args']['body']['code_verifier']);
        $this->assertSame('authorization_code', $tokenCall['args']['body']['grant_type']);
        $this->assertSame(self::CALLBACK, $tokenCall['args']['body']['redirect_uri']);
        $this->assertArrayNotHasKey(
            'client_secret',
            $tokenCall['args']['body'],
            'a public client must not send an empty secret',
        );
    }

    public function test_rejects_a_token_from_the_wrong_issuer(): void
    {
        $token = KeyFixture::primary()->sign(['iss' => 'https://evil.test']);

        try {
            $this->completeLogin($token);
            $this->fail('expected the callback to be refused');
        } catch (WpDieException $died) {
            $this->assertStringContainsString('Issuer mismatch', $died->body);
            $this->assertSame(401, $died->status());
        }
        $this->assertSame([], WpState::$authCookies);
    }

    public function test_rejects_a_token_minted_for_a_different_site(): void
    {
        // The multi-tenant case: one issuer signs for the whole fleet, so the audience is the only
        // thing that keeps another site's token from working here.
        $token = KeyFixture::primary()->sign(['aud' => 'someoneelse']);

        try {
            $this->completeLogin($token);
            $this->fail('expected the callback to be refused');
        } catch (WpDieException $died) {
            $this->assertStringContainsString('Audience mismatch', $died->body);
            $this->assertSame(401, $died->status());
        }
        $this->assertSame([], WpState::$authCookies);
    }

    public function test_accepts_a_token_whose_audience_list_includes_this_site(): void
    {
        $redirect = $this->completeLogin(
            KeyFixture::primary()->sign(['aud' => ['someoneelse', self::CLIENT_ID]]),
        );

        $this->assertTrue($redirect->safe);
        $this->assertCount(1, WpState::$authCookies);
    }

    public function test_rejects_a_forged_token_at_the_callback(): void
    {
        try {
            $this->completeLogin(KeyFixture::primary()->unsignedNoneToken());
            $this->fail('expected the callback to be refused');
        } catch (WpDieException $died) {
            $this->assertStringContainsString('Token validation failed', $died->body);
            $this->assertSame(401, $died->status());
        }
        $this->assertSame([], WpState::$authCookies);
    }

    public function test_reports_a_provider_error_response(): void
    {
        $params = $this->startLogin();
        WpState::respondJson(self::TOKEN_ENDPOINT, [
            'error' => 'invalid_grant',
            'error_description' => 'Authorization code expired.',
        ]);
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        try {
            OidcClient::handleCallback();
            $this->fail('expected the callback to be refused');
        } catch (WpDieException $died) {
            $this->assertStringContainsString('Authorization code expired', $died->body);
            $this->assertSame(502, $died->status());
        }
    }

    public function test_rejects_a_token_response_with_no_id_token(): void
    {
        $params = $this->startLogin();
        WpState::respondJson(self::TOKEN_ENDPOINT, ['access_token' => 'opaque']);
        $_GET = ['jwt_auth_callback' => '1', 'code' => 'auth-code', 'state' => $params['state']];

        try {
            OidcClient::handleCallback();
            $this->fail('expected the callback to be refused');
        } catch (WpDieException $died) {
            $this->assertStringContainsString('No ID token', $died->body);
            $this->assertSame(502, $died->status());
        }
    }

    public function test_confines_the_post_login_redirect_to_this_site(): void
    {
        // redirect_to is attacker-controllable, so an off-site value must fall back home rather
        // than turning the login into an open redirector.
        $_REQUEST['redirect_to'] = 'https://evil.test/steal';

        $redirect = $this->completeLogin();

        $this->assertSame('https://example.test/', $redirect->location);
    }

    // ---------------------------------------------------------------------
    // Registration closed
    // ---------------------------------------------------------------------

    public function test_a_refused_signin_ends_the_provider_session_and_comes_back_to_the_notice(): void
    {
        // Without the round trip the provider would keep the session and the next attempt would
        // silently replay the same rejected identity, with no way to pick a different account.
        WpState::$usersCanRegister = false;

        $redirect = $this->completeLogin();

        $this->assertFalse($redirect->safe, 'the bounce leaves the site, so not wp_safe_redirect');
        $this->assertStringStartsWith(self::ISSUER . '/logout', $redirect->location);
        $this->assertSame(
            'https://example.test/?jwt_auth_denied=1',
            $redirect->query()['post_logout_redirect_uri'],
        );

        $this->assertSame([], WpState::$users, 'no account may be created');
        $this->assertSame([], WpState::$authCookies, 'and no session established');
        $this->assertTrue(WpState::$authCookieCleared, 'a stale cookie must not survive the refusal');
    }

    public function test_a_refused_signin_shows_the_notice_when_the_provider_cannot_be_signed_out_of(): void
    {
        WpState::$usersCanRegister = false;
        $this->registerDiscovery(['end_session_endpoint' => null]);

        try {
            $this->completeLogin();
            $this->fail('expected the sign-in to be refused');
        } catch (WpDieException $died) {
            $this->assertSame(403, $died->status());
            $this->assertStringContainsString('not accepting new accounts', $died->body);
        }

        $this->assertSame([], WpState::$users);
        $this->assertSame([], WpState::$authCookies);
    }

    public function test_the_return_from_the_provider_renders_the_notice(): void
    {
        $_GET = ['jwt_auth_denied' => '1'];

        $this->expectException(WpDieException::class);
        $this->expectExceptionMessage('not accepting new accounts');
        OidcClient::handleDeniedReturn();
    }

    public function test_ordinary_requests_pass_the_notice_handler_untouched(): void
    {
        $_GET = [];
        OidcClient::handleDeniedReturn();

        $this->addToAssertionCount(1);
    }

    public function test_a_member_following_a_stale_denial_link_is_not_shown_the_notice(): void
    {
        $_GET = ['jwt_auth_denied' => '1'];
        WpState::$loggedIn = true;

        OidcClient::handleDeniedReturn();

        $this->addToAssertionCount(1);
    }

    public function test_an_existing_user_still_signs_in_when_registration_is_closed(): void
    {
        WpState::$usersCanRegister = false;
        WpState::addUser('user@example.test', 'pin:abc123');

        $redirect = $this->completeLogin();

        $this->assertTrue($redirect->safe);
        $this->assertCount(1, WpState::$authCookies);
    }

    // ---------------------------------------------------------------------
    // Discovery and logout
    // ---------------------------------------------------------------------

    public function test_discovery_is_cached(): void
    {
        OidcClient::discover();
        OidcClient::discover();

        $discoveryCalls = array_filter(
            WpState::$httpCalls,
            static fn (array $c): bool => str_contains($c['url'], 'openid-configuration'),
        );
        $this->assertCount(1, $discoveryCalls);
    }

    public function test_rejects_a_discovery_document_that_is_not_one(): void
    {
        WpState::respondJson(self::ISSUER . '/.well-known/openid-configuration', ['hello' => 'world']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid OIDC discovery document');
        OidcClient::discover();
    }

    public function test_jwks_uri_comes_from_discovery_when_not_configured(): void
    {
        $this->assertSame(self::JWKS_URI, OidcClient::jwksUri());
    }

    public function test_logout_bounces_through_the_providers_end_session_endpoint(): void
    {
        try {
            OidcClient::handleLogout();
            $this->fail('expected a redirect to the provider');
        } catch (WpRedirectException $redirect) {
            $this->assertStringStartsWith(self::ISSUER . '/logout', $redirect->location);
            $this->assertSame('https://example.test/', $redirect->query()['post_logout_redirect_uri']);
        }
    }

    public function test_logout_is_a_no_op_when_the_provider_is_unreachable(): void
    {
        // A provider outage must not trap the user in a broken logout.
        WpState::$httpResponses = [];
        WpState::$transients = [];

        OidcClient::handleLogout();

        $this->addToAssertionCount(1);
    }
}
