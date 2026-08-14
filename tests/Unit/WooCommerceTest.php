<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpState;
use JwtAuth\WooCommerce;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(WooCommerce::class)]
final class WooCommerceTest extends WordPressTestCase
{
    public function test_renders_a_sign_in_button_pointing_at_the_wordpress_login(): void
    {
        // wp_login_url is what the plugin hooks to start the OIDC redirect, so the button has to
        // route through it rather than linking the provider directly.
        WpState::$isAccountPage = true;

        ob_start();
        WooCommerce::renderSsoButton();
        $html = (string) ob_get_clean();

        $this->assertStringContainsString('Sign in with SSO', $html);
        $this->assertStringContainsString('wp-login.php', $html);
        $this->assertStringContainsString('jwt-auth-sso', $html);
    }

    public function test_marks_the_button_with_the_class_the_fallback_script_looks_for(): void
    {
        // assets/src/sso-button.ts skips any form already containing .jwt-auth-sso. That contract is
        // the only thing stopping the script adding a second button under this one, and it is a
        // string shared across two languages — so assert the exact marker, not just its presence
        // somewhere in the markup.
        WpState::$isAccountPage = true;

        ob_start();
        WooCommerce::renderSsoButton();
        $html = (string) ob_get_clean();

        $this->assertStringContainsString('<div class="jwt-auth-sso">', $html);
    }

    public function test_returns_the_user_to_my_account_when_that_is_where_they_started(): void
    {
        WpState::$isAccountPage = true;

        ob_start();
        WooCommerce::renderSsoButton();
        $html = (string) ob_get_clean();

        $this->assertStringContainsString(rawurlencode('https://example.test/my-account/'), $html);
    }

    public function test_returns_the_user_home_from_anywhere_else(): void
    {
        ob_start();
        WooCommerce::renderSsoButton();
        $html = (string) ob_get_clean();

        $this->assertStringContainsString(rawurlencode('https://example.test/'), $html);
        $this->assertStringNotContainsString('my-account', $html);
    }

    public function test_enqueues_the_fallback_script_on_the_account_page(): void
    {
        WpState::$isAccountPage = true;

        WooCommerce::enqueueAssets();

        $this->assertContains('jwt-auth-woo', WpState::$enqueuedScripts);
    }

    public function test_hands_the_script_its_config_as_a_typed_object_on_window(): void
    {
        // wp_add_inline_script(…, 'before'), not wp_localize_script: the shape has to match
        // JwtAuthConfig in types/globals.d.ts, and wp_localize_script would stringify every value.
        WpState::$isAccountPage = true;

        WooCommerce::enqueueAssets();

        $this->assertCount(1, WpState::$inlineScripts);
        $inline = WpState::$inlineScripts[0];

        $this->assertSame('jwt-auth-woo', $inline['handle']);
        $this->assertSame('before', $inline['position']);

        $json = (string) preg_replace('/^window\.jwtAuth = |;$/', '', $inline['data']);
        /** @var array{loginUrl: string, buttonLabel: string} $config */
        $config = json_decode($json, associative: true);

        $this->assertSame('Sign in with SSO', $config['buttonLabel']);
        $this->assertStringContainsString('wp-login.php', $config['loginUrl']);
    }

    public function test_versions_the_script_from_the_build_manifest(): void
    {
        // The manifest's content hash is what busts the browser cache. A hardcoded version string
        // here would leave every visitor on the previously cached bundle after a fix ships.
        WpState::$isAccountPage = true;

        WooCommerce::enqueueAssets();

        $this->assertSame(
            ['jwt-auth-woo' => 'testfixture000000000'],
            WpState::$scriptVersions,
        );
    }

    public function test_enqueues_on_checkout_too(): void
    {
        WpState::$isCheckout = true;

        WooCommerce::enqueueAssets();

        $this->assertContains('jwt-auth-woo', WpState::$enqueuedScripts);
    }

    public function test_loads_nothing_on_unrelated_pages(): void
    {
        // Neither an account page nor checkout: no reason to ship the fallback script.
        WooCommerce::enqueueAssets();

        $this->assertSame([], WpState::$enqueuedScripts);
        $this->assertSame([], WpState::$inlineScripts);
    }

    public function test_loads_nothing_when_the_bundle_has_not_been_built(): void
    {
        // A source checkout that skipped `npm run build`. The server-rendered button still covers
        // every form WooCommerce renders, so the page is fine — but enqueuing a script that 404s
        // would put a console error on every My Account view.
        WpState::$isAccountPage = true;
        WpState::$pluginDir = WpState::UNBUILT_FIXTURE;

        WooCommerce::enqueueAssets();

        $this->assertSame([], WpState::$enqueuedScripts);
        $this->assertSame([], WpState::$inlineScripts);
    }
}
