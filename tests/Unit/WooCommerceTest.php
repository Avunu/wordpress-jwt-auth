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

    public function test_enqueues_the_block_form_script_on_the_account_page(): void
    {
        WpState::$isAccountPage = true;

        WooCommerce::enqueueAssets();

        $this->assertContains('jwt-auth-woo', WpState::$enqueuedScripts);
        $this->assertSame('jwt-auth-woo', WpState::$localizedScripts[0]['handle']);
        $this->assertSame(
            'Sign in with SSO',
            WpState::$localizedScripts[0]['data']['buttonLabel'],
        );
        $this->assertStringContainsString(
            'wp-login.php',
            WpState::$localizedScripts[0]['data']['loginUrl'],
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
        // Neither an account page nor checkout: no reason to ship the override script.
        WooCommerce::enqueueAssets();

        $this->assertSame([], WpState::$enqueuedScripts);
        $this->assertSame([], WpState::$localizedScripts);
    }
}
