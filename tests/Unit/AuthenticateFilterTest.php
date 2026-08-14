<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpState;
use JwtAuth\Validator;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * `authenticate` is a filter, so the login is decided by whatever the LAST callback returns.
 * Testing blockDirectAuth() in isolation — which is all the previous suite did — cannot see that,
 * and the plugin's headline control was registered at priority 1, below WordPress core's own
 * handlers at 20. Core authenticated the credential and returned a WP_User, overwriting the
 * refusal, and the suite stayed green while password login kept working on every path that does
 * not pass through wp-login.php.
 *
 * These tests run the real chain. The core-like callback below is deliberately unconditional: the
 * property under test is not "core behaves in a particular way" but "our refusal survives a later
 * callback that successfully authenticates", which holds regardless of core's internals.
 */
#[CoversClass(Validator::class)]
final class AuthenticateFilterTest extends WordPressTestCase
{
    /** The plugin's registration, at the priority jwt-auth.php uses. */
    private function registerPluginBlock(int $priority = 30): void
    {
        add_filter('authenticate', Validator::blockDirectAuth(...), $priority, 3);
    }

    /** Stands in for wp_authenticate_username_password and friends, which core registers at 20. */
    private function registerCorePasswordHandler(string $login, string $password): void
    {
        $user = WpState::addUser($login);
        add_filter(
            'authenticate',
            static fn (mixed $carry, string $u, string $p): mixed
                => $u === $login && $p === $password ? $user : $carry,
            20,
            3,
        );
    }

    public function test_a_correct_password_is_still_refused(): void
    {
        // The whole finding in one assertion: core authenticates successfully at priority 20, and
        // the plugin must still have the last word.
        $this->registerCorePasswordHandler('admin', 'correct-horse');
        $this->registerPluginBlock();

        $result = wp_authenticate('admin', 'correct-horse');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('jwt_auth_required', $result->get_error_code());
    }

    public function test_registering_below_core_is_what_made_it_a_no_op(): void
    {
        // Pins the actual defect, so nobody "tidies" the priority back down. At 1 the refusal is
        // produced and then discarded by the priority-20 handler.
        $this->registerCorePasswordHandler('admin', 'correct-horse');
        $this->registerPluginBlock(priority: 1);

        $result = wp_authenticate('admin', 'correct-horse');

        $this->assertInstanceOf(\WP_User::class, $result, 'demonstrates the bug this fix removes');
    }

    public function test_a_wrong_password_is_refused_without_revealing_which_part_was_wrong(): void
    {
        $this->registerCorePasswordHandler('admin', 'correct-horse');
        $this->registerPluginBlock();

        $result = wp_authenticate('admin', 'wrong');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('jwt_auth_required', $result->get_error_code());
    }

    public function test_the_refusal_is_identical_for_a_real_and_an_unknown_account(): void
    {
        // No user-enumeration oracle: whether the credential was valid changes nothing observable.
        $this->registerCorePasswordHandler('admin', 'correct-horse');
        $this->registerPluginBlock();

        $known = wp_authenticate('admin', 'correct-horse');
        $unknown = wp_authenticate('nobody', 'whatever');

        $this->assertSame($known->get_error_code(), $unknown->get_error_code());
        $this->assertSame($known->get_error_message(), $unknown->get_error_message());
    }

    public function test_application_passwords_and_xmlrpc_take_the_same_path(): void
    {
        // Both authenticate through the same filter, so covering it once covers them all. This is
        // why the fix is a priority change rather than a new guard per entry point.
        $this->registerCorePasswordHandler('editor', 'app-password-value');
        $this->registerPluginBlock();

        $this->assertInstanceOf(\WP_Error::class, wp_authenticate('editor', 'app-password-value'));
        $this->assertSame([], WpState::$authCookies, 'nothing may be issued a session');
    }

    public function test_cron_and_wp_cli_still_authenticate(): void
    {
        // The pass-through exists so scheduled work keeps running; at priority 30 the value handed
        // back is core's WP_User rather than the null it used to receive.
        WpState::$doingCron = true;
        $this->registerCorePasswordHandler('cronuser', 'secret');
        $this->registerPluginBlock();

        $this->assertInstanceOf(\WP_User::class, wp_authenticate('cronuser', 'secret'));
    }

    public function test_an_empty_submission_keeps_wordpress_own_error(): void
    {
        // Nothing was submitted, so there is no credential to refuse; core's empty-field error is
        // the better message and wp_authenticate() treats those codes specially.
        add_filter(
            'authenticate',
            static fn (mixed $carry): mixed => new \WP_Error('empty_username', 'Empty username.'),
            20,
            3,
        );
        $this->registerPluginBlock();

        $result = wp_authenticate('', '');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('empty_username', $result->get_error_code());
    }
}
