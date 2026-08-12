<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\AuthMode;
use JwtAuth\Config;
use JwtAuth\Tests\Support\WordPressTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Constants are process-global and cannot be redefined, so the bootstrap defines only ISSUER and
 * CLIENT_ID. Everything else is left undefined on purpose, which makes this suite an assertion
 * about the *defaults* a minimally-configured site actually gets.
 */
#[CoversClass(Config::class)]
final class ConfigTest extends WordPressTestCase
{
    public function test_reads_the_configured_issuer_and_client(): void
    {
        $this->assertSame(self::ISSUER, Config::issuer());
        $this->assertSame(self::CLIENT_ID, Config::clientId());
    }

    public function test_defining_a_client_id_selects_oidc_mode(): void
    {
        $this->assertSame(AuthMode::Oidc, Config::detectMode());
    }

    public function test_an_unset_client_secret_means_a_pkce_only_public_client(): void
    {
        $this->assertSame('', Config::clientSecret());
    }

    public function test_optional_overrides_are_null_when_undefined(): void
    {
        // Each of these, when null, selects a different code path: discovery for the JWKS URI,
        // client_id for the audience, and the discovered end_session_endpoint for logout.
        $this->assertNull(Config::jwksUri());
        $this->assertNull(Config::aud());
        $this->assertNull(Config::logoutUrl());
        $this->assertNull(Config::tokenCookie());
        $this->assertNull(Config::tokenHeader());
    }

    public function test_user_creation_defaults(): void
    {
        $this->assertSame('subscriber', Config::defaultRole());
    }

    public function test_claim_names_default_to_the_standard_oidc_set(): void
    {
        $this->assertSame('email', Config::claimEmail());
        $this->assertSame('given_name', Config::claimFirstName());
        $this->assertSame('family_name', Config::claimLastName());
        $this->assertSame('name', Config::claimName());
    }

    public function test_ux_defaults(): void
    {
        $this->assertSame('/', Config::redirect());
        $this->assertSame('SSO', Config::providerName());
    }

    public function test_callback_url_is_the_site_root_flagged_for_the_plugin(): void
    {
        // This exact string is what the provider's redirect-URI allowlist has to contain, so it is
        // worth pinning rather than leaving implicit.
        $this->assertSame(self::CALLBACK, Config::callbackUrl());
    }
}
