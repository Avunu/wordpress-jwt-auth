<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\Registration;
use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpDieException;
use JwtAuth\Tests\Support\WpState;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * The provisioning switch and the notice behind it. isSignInRequest() is the interesting half: in
 * proxy mode it decides between "browse the public site anonymously" and "stop and explain", and it
 * runs on every unauthenticated request, so a false positive is an outage.
 */
#[CoversClass(Registration::class)]
final class RegistrationTest extends WordPressTestCase
{
    public function test_tracks_the_wordpress_membership_setting(): void
    {
        WpState::$usersCanRegister = true;
        $this->assertTrue(Registration::isOpen());

        WpState::$usersCanRegister = false;
        $this->assertFalse(Registration::isOpen());
    }

    public function test_the_notice_halts_the_request_with_a_403(): void
    {
        try {
            Registration::deny();
            $this->fail('expected the notice to halt the request');
        } catch (WpDieException $died) {
            $this->assertSame(403, $died->status());
            $this->assertStringContainsString('not accepting new accounts', $died->body);
        }
    }

    // ---------------------------------------------------------------------
    // Which requests get told
    // ---------------------------------------------------------------------

    public function test_an_ordinary_front_end_request_is_left_alone(): void
    {
        $this->assertFalse(Registration::isSignInRequest());
    }

    public function test_wp_admin_and_wp_login_are_worth_explaining(): void
    {
        WpState::$isAdmin = true;
        $this->assertTrue(Registration::isSignInRequest());

        WpState::$isAdmin = false;
        $GLOBALS['pagenow'] = 'wp-login.php';
        $this->assertTrue(Registration::isSignInRequest());
    }

    public function test_stays_quiet_for_ajax_even_though_it_reports_as_admin(): void
    {
        // admin-ajax.php sets is_admin(); an error page here replaces the JSON a script is waiting
        // for, breaking the front end of a site the visitor is otherwise allowed to read.
        WpState::$isAdmin = true;
        WpState::$doingAjax = true;

        $this->assertFalse(Registration::isSignInRequest());
    }

    public function test_stays_quiet_for_cron(): void
    {
        WpState::$isAdmin = true;
        WpState::$doingCron = true;

        $this->assertFalse(Registration::isSignInRequest());
    }

    public function test_never_blocks_a_logout(): void
    {
        $GLOBALS['pagenow'] = 'wp-login.php';
        $_REQUEST['action'] = 'logout';

        $this->assertFalse(Registration::isSignInRequest());
    }
}
