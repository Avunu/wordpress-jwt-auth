<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\Config;
use JwtAuth\ExclusiveLogin;
use JwtAuth\SsoButton;
use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpDieException;
use JwtAuth\Tests\Support\WpState;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * JWT_AUTH_EXCLUSIVE, hook by hook.
 *
 * Note what this suite can and cannot prove. The callbacks are pure enough to assert directly, and
 * the hook *addresses* — name and priority — are recorded by the fake, which is the part that
 * decides whether a refusal runs at all. What it cannot prove is that WooCommerce still registers
 * `WC_Form_Handler::process_reset_password` on `wp_loaded` at priority 20, or that a browser puts
 * the fields inside `<template>` where nothing can submit them. Those live in tests/playground,
 * against real WooCommerce and real Chrome — the same division the `authenticate` priority bug
 * taught this repo to keep.
 */
#[CoversClass(ExclusiveLogin::class)]
#[CoversClass(SsoButton::class)]
final class ExclusiveLoginTest extends WordPressTestCase
{
    // -------------------------------------------------------------------------
    // Core: wp_login_form()
    // -------------------------------------------------------------------------

    /**
     * Reassemble what wp_login_form() builds, with the plugin's two filters in their real places.
     *
     * Core interpolates `login_form_top` immediately after the opening form tag and
     * `login_form_bottom` immediately before the closing one, so this is the whole markup a visitor
     * would receive — the only way to assert that the fields end up somewhere inert is to look at
     * the assembled string rather than either filter alone.
     */
    private function renderCoreLoginForm(string $redirect = ''): string
    {
        $args = ['redirect' => $redirect];

        return '<form name="loginform" id="loginform" action="https://example.test/wp-login.php" method="post">'
            . ExclusiveLogin::openReplacement('', $args)
            . '<p class="login-username"><input type="text" name="log" id="user_login" /></p>'
            . '<p class="login-password"><input type="password" name="pwd" id="user_pass" /></p>'
            . '<p class="login-submit"><input type="submit" name="wp-submit" /></p>'
            . ExclusiveLogin::closeReplacement('')
            . '</form>';
    }

    public function test_the_core_login_form_offers_the_button_and_nothing_else(): void
    {
        $html = $this->renderCoreLoginForm();

        $this->assertStringContainsString('jwt-auth-sso', $html);
        $this->assertStringContainsString('Sign in with SSO', $html);
    }

    public function test_the_password_fields_end_up_inside_an_inert_template(): void
    {
        // `<template>` is the whole mechanism: wp_login_form() offers no hook that can suppress the
        // fields, so they are put where a browser will not render, submit or autofill them. Assert
        // the ordering that makes that true — button first, then the template, with both credential
        // inputs between its tags.
        $html = $this->renderCoreLoginForm();

        $button   = strpos($html, 'jwt-auth-sso');
        $open     = strpos($html, '<template');
        $login    = strpos($html, 'name="log"');
        $password = strpos($html, 'name="pwd"');
        $submit   = strpos($html, 'name="wp-submit"');
        $close    = strpos($html, '</template>');

        $this->assertIsInt($button);
        $this->assertIsInt($open);
        $this->assertIsInt($close);

        $this->assertLessThan($open, $button, 'the button must be outside the suppressed block');
        foreach (['username' => $login, 'password' => $password, 'submit' => $submit] as $label => $at) {
            $this->assertIsInt($at);
            $this->assertGreaterThan($open, $at, "the {$label} field must be inside the template");
            $this->assertLessThan($close, $at, "the {$label} field must be inside the template");
        }
    }

    public function test_the_visible_form_is_closed_before_the_button_so_the_button_is_not_a_field(): void
    {
        // The early `</form>` is what leaves the rendered form empty. Core then appends its own
        // `</form>`, which lands with no form open — an HTML5 parse error every parser handles by
        // ignoring the token. That last part is Chrome's to confirm; this pins the intent.
        $html = $this->renderCoreLoginForm();

        $this->assertSame(1, substr_count($html, '<form'), 'no second form element is introduced');
        $this->assertSame(2, substr_count($html, '</form>'), 'one closes the form early, one is core\'s');
        $this->assertLessThan(
            strpos($html, 'jwt-auth-sso'),
            strpos($html, '</form>'),
            'the form closes before the button',
        );
    }

    public function test_the_button_returns_the_visitor_where_the_form_would_have(): void
    {
        // wp_login_form()'s `redirect` argument is the caller's post-login destination; dropping it
        // would land everyone on the site root regardless of which page hosted the form.
        $html = $this->renderCoreLoginForm('https://example.test/members/');

        $this->assertStringContainsString(rawurlencode('https://example.test/members/'), $html);
    }

    public function test_a_form_rendered_by_a_plugin_that_passes_no_redirect_still_works(): void
    {
        $html = $this->renderCoreLoginForm();

        $this->assertStringContainsString('wp-login.php', $html);
        $this->assertStringNotContainsString('redirect_to', $html);
    }

    public function test_other_plugins_content_is_kept_on_both_hooks(): void
    {
        // Priority 99 on `login_form_top` and 1 on `login_form_bottom` exist so that a captcha or a
        // notice another plugin adds is not swallowed by the template or dropped on the floor.
        $top    = ExclusiveLogin::openReplacement('<!--theirs-top-->', ['redirect' => '']);
        $bottom = ExclusiveLogin::closeReplacement('<!--theirs-bottom-->');

        $this->assertStringStartsWith('<!--theirs-top-->', $top);
        $this->assertStringEndsWith('<!--theirs-bottom-->', $bottom);
        $this->assertStringStartsWith('</template>', $bottom);
    }

    // -------------------------------------------------------------------------
    // Core: the Login/out block
    // -------------------------------------------------------------------------

    public function test_the_login_block_is_demoted_from_a_form_to_a_link(): void
    {
        // core/loginout renders wp_login_form() when "Display login as form" is ticked. Clearing the
        // attribute before render drops it to wp_loginout() — a link to wp-login.php, which is where
        // the provider redirect lives.
        $parsed = ExclusiveLogin::demoteLoginBlock([
            'blockName' => 'core/loginout',
            'attrs'     => ['displayLoginAsForm' => true, 'redirectToCurrent' => true],
        ]);

        $this->assertIsArray($parsed);
        $this->assertFalse($parsed['attrs']['displayLoginAsForm']);
        $this->assertTrue($parsed['attrs']['redirectToCurrent'], 'unrelated attributes are left alone');
    }

    public function test_a_login_block_with_no_attributes_at_all_is_handled(): void
    {
        // WP_Block_Parser omits `attrs` entirely for a block saved with no settings.
        $parsed = ExclusiveLogin::demoteLoginBlock(['blockName' => 'core/loginout']);

        $this->assertIsArray($parsed);
        $this->assertFalse($parsed['attrs']['displayLoginAsForm']);
    }

    public function test_every_other_block_passes_through_untouched(): void
    {
        // render_block_data runs for every block on every page, so the guard is a hot path as well
        // as a correctness one.
        $paragraph = ['blockName' => 'core/paragraph', 'attrs' => ['content' => 'hello']];

        $this->assertSame($paragraph, ExclusiveLogin::demoteLoginBlock($paragraph));
        $this->assertSame('not a block', ExclusiveLogin::demoteLoginBlock('not a block'));
    }

    // -------------------------------------------------------------------------
    // Core: wp-login.php
    // -------------------------------------------------------------------------

    public function test_the_sign_in_screen_is_refused_when_the_provider_could_not_be_reached(): void
    {
        // In OIDC mode this hook is only reached because OidcClient::redirectToProvider() gave up on
        // discovery. Without the switch that falls through to core's form, which is safe but is a
        // password box on a site that has none; with it, the visitor is told what actually happened.
        $_REQUEST['action'] = 'login';

        try {
            ExclusiveLogin::blockLoginScreen();
            $this->fail('expected wp_die()');
        } catch (WpDieException $e) {
            $this->assertSame(503, $e->status());
            $this->assertStringContainsString('temporarily unavailable', $e->body);
            $this->assertStringContainsString('SSO', $e->body);
        }
    }

    public function test_registration_and_password_reset_screens_are_refused_too(): void
    {
        foreach (['register', 'lostpassword', 'retrievepassword', 'resetpass', 'rp'] as $action) {
            $_REQUEST['action'] = $action;

            try {
                ExclusiveLogin::blockLoginScreen();
                $this->fail("expected wp_die() for action={$action}");
            } catch (WpDieException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_an_absent_action_is_treated_as_the_login_screen(): void
    {
        // wp-login.php defaults $action to 'login' when the parameter is missing, which is how the
        // bare URL behaves — the common case, and the one a whitelist keyed on the literal would miss.
        $this->expectException(WpDieException::class);

        ExclusiveLogin::blockLoginScreen();
    }

    public function test_the_screen_still_does_everything_that_is_not_a_login(): void
    {
        // wp-login.php is also how a visitor unlocks a password-protected post, confirms a privacy
        // request, enters recovery mode, and signs out. Blocking the screen wholesale would break
        // each of those, and locking an administrator out of `logout` is the worst of them.
        foreach (
            [
                'logout',
                'postpass',
                'confirmaction',
                'confirm_admin_email',
                'checkemail',
                'enter_recovery_mode',
            ] as $action
        ) {
            $_REQUEST['action'] = $action;

            ExclusiveLogin::blockLoginScreen();
            $this->addToAssertionCount(1);
        }
    }

    // -------------------------------------------------------------------------
    // Password reset and registration refusals
    // -------------------------------------------------------------------------

    public function test_a_lost_password_request_is_refused_with_a_reason_and_a_way_forward(): void
    {
        // `allow_password_reset` already stops the key being minted, but its refusal reads as
        // "Password reset is not allowed for this user" — a per-user restriction that is not what is
        // happening. This hook replaces that with the truth.
        $errors = new \WP_Error();

        ExclusiveLogin::refuseLostPassword($errors);

        $this->assertSame('jwt_auth_required', $errors->get_error_code());
        $this->assertStringContainsString('does not use passwords', $errors->get_error_message());
        $this->assertStringContainsString('wp-login.php', $errors->get_error_message());
    }

    public function test_woocommerce_registration_is_refused_on_its_own_extension_point(): void
    {
        // Belt to the remove_action() braces. WC_Form_Handler::process_registration() reads only the
        // nonce and the POST body — never the setting that draws the form — so a crafted request
        // reaches wc_create_new_customer() and the wc_set_customer_auth_cookie() call after it.
        $errors = new \WP_Error();

        $returned = ExclusiveLogin::refuseWooRegistration($errors);

        $this->assertSame($errors, $returned, 'the filter must hand back the bag it was given');
        $this->assertSame('jwt_auth_required', $errors->get_error_code());
    }

    public function test_a_refusal_hook_handed_something_other_than_an_error_bag_does_not_explode(): void
    {
        $this->assertNull(ExclusiveLogin::refuseWooRegistration(null));
    }

    // -------------------------------------------------------------------------
    // WooCommerce template substitution
    // -------------------------------------------------------------------------

    /**
     * @return list<array{0: string}>
     */
    public static function wooTemplateProvider(): array
    {
        return [
            ['myaccount/form-login.php'],
            ['myaccount/form-lost-password.php'],
            ['myaccount/form-reset-password.php'],
            ['global/form-login.php'],
            ['checkout/form-login.php'],
            ['auth/form-login.php'],
        ];
    }

    #[DataProvider('wooTemplateProvider')]
    public function test_every_credential_template_resolves_to_one_this_plugin_ships(string $name): void
    {
        // Reading the real plugin root rather than a fixture is the point: a template renamed here
        // and not there would leave WooCommerce's password form in place, and wooTemplate() falls
        // back silently by design, so a fixture would let that pass.
        WpState::$pluginDir = WpState::PLUGIN_ROOT;

        $wooPath = '/wp-content/plugins/woocommerce/templates/' . $name;
        $located = ExclusiveLogin::wooTemplate($wooPath, $name);

        $this->assertIsString($located);
        $this->assertNotSame($wooPath, $located, 'WooCommerce\'s own template must not survive');
        $this->assertStringEndsWith('templates/woocommerce/' . $name, $located);
        $this->assertFileExists($located);
    }

    public function test_templates_with_nothing_to_do_with_credentials_are_left_alone(): void
    {
        WpState::$pluginDir = WpState::PLUGIN_ROOT;

        foreach (['cart/cart.php', 'myaccount/dashboard.php', 'myaccount/form-edit-account.php'] as $name) {
            $wooPath = '/wp-content/plugins/woocommerce/templates/' . $name;

            $this->assertSame($wooPath, ExclusiveLogin::wooTemplate($wooPath, $name));
        }
    }

    public function test_a_source_checkout_without_the_templates_falls_back_rather_than_blanking_the_page(): void
    {
        // wc_get_template() renders *nothing at all* when a filtered path does not exist, so pointing
        // at a missing file would empty My Account instead of replacing its form. Only the zip build
        // guarantees templates/ is present.
        WpState::$pluginDir = WpState::UNBUILT_FIXTURE;

        $wooPath = '/wp-content/plugins/woocommerce/templates/myaccount/form-login.php';

        $this->assertSame($wooPath, ExclusiveLogin::wooTemplate($wooPath, 'myaccount/form-login.php'));
    }

    // -------------------------------------------------------------------------
    // Registration: where the hooks land
    // -------------------------------------------------------------------------

    public function test_the_core_hooks_are_registered_where_they_have_the_last_word(): void
    {
        ExclusiveLogin::register();

        $this->assertArrayHasKey(99, WpState::$filters['login_form_top'] ?? []);
        $this->assertArrayHasKey(1, WpState::$filters['login_form_bottom'] ?? []);
        $this->assertArrayHasKey(10, WpState::$filters['render_block_data'] ?? []);

        // Priority 20 puts this after OidcClient::redirectToProvider() at 10, so the redirect is
        // still tried first and this only speaks when it declined to.
        $this->assertArrayHasKey(20, WpState::$addedActions['login_init'] ?? []);
    }

    public function test_password_reset_keys_are_refused_at_source(): void
    {
        ExclusiveLogin::register();

        $this->assertFalse(
            apply_filters('allow_password_reset', true, 1),
            'both core and WooCommerce ask this before calling get_password_reset_key()',
        );
        $this->assertArrayHasKey('lostpassword_post', WpState::$addedActions);
    }

    public function test_account_creation_that_would_mint_a_password_is_switched_off(): void
    {
        ExclusiveLogin::register();

        // The checkout "create an account" checkbox, on both the classic and block checkouts.
        // Priority 100 beats WC_Checkout's own setter, which registers at 0.
        $this->assertFalse(apply_filters('woocommerce_checkout_registration_enabled', true));

        // The order-confirmation "Create an account with …" block, which has no filter of its own.
        $this->assertSame('no', apply_filters('option_woocommerce_enable_delayed_account_creation', 'yes'));
        $this->assertSame(
            'no',
            apply_filters('default_option_woocommerce_enable_delayed_account_creation', 'yes'),
            'the option defaults to yes when absent, so the default has to be filtered too',
        );
    }

    public function test_the_woocommerce_handlers_that_hand_out_sessions_are_unhooked(): void
    {
        // These are the paths that never reach the `authenticate` filter:
        // WC_Shortcode_My_Account::reset_password() and WC_Form_Handler::process_registration() both
        // end in wc_set_customer_auth_cookie(), so filtering credentials cannot touch them.
        ExclusiveLogin::register();

        $removed = array_map(
            static fn(array $r): string => "{$r['hook']}:{$r['callback']}@{$r['priority']}",
            WpState::$removedActions,
        );

        $this->assertContains('wp_loaded:WC_Form_Handler::process_registration@20', $removed);
        $this->assertContains('wp_loaded:WC_Form_Handler::process_lost_password@20', $removed);
        $this->assertContains('wp_loaded:WC_Form_Handler::process_reset_password@20', $removed);
        $this->assertContains('template_redirect:WC_Form_Handler::redirect_reset_password_link@10', $removed);
    }

    public function test_woocommerce_s_own_login_handler_is_deliberately_left_in_place(): void
    {
        // process_login() ends in wp_signon() and is therefore already refused by blockDirectAuth().
        // Leaving it registered is what makes a third-party or AJAX login form that posts there show
        // "Direct login is disabled — sign in with SSO" rather than appear to do nothing.
        ExclusiveLogin::register();

        $removed = array_column(WpState::$removedActions, 'callback');

        $this->assertNotContains('WC_Form_Handler::process_login', $removed);
    }

    public function test_the_button_label_follows_the_configured_provider_name(): void
    {
        $this->assertSame('Sign in with SSO', SsoButton::label());
        $this->assertSame('Sign in with ' . Config::providerName(), SsoButton::label());
    }

    public function test_the_shared_marker_class_is_the_one_the_fallback_script_looks_for(): void
    {
        // assets/src/sso-button.ts skips any form already containing .jwt-auth-sso, and in exclusive
        // mode that guard is what stops the script emptying a form the server already replaced. The
        // string spans two languages, so pin it.
        $this->assertSame('jwt-auth-sso', SsoButton::MARKER_CLASS);
        $this->assertStringContainsString(
            '<div class="jwt-auth-sso">',
            SsoButton::html('https://example.test/wp-login.php'),
        );
    }
}
