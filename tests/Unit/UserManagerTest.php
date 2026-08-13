<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\Claims;
use JwtAuth\Tests\Support\WordPressTestCase;
use JwtAuth\Tests\Support\WpState;
use JwtAuth\UserManager;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Account resolution. The lookup order is the whole security-relevant contract: match on the
 * provider's subject first so a user who changes their email keeps their account, and fall back to
 * email only to adopt accounts that predate SSO.
 */
#[CoversClass(UserManager::class)]
final class UserManagerTest extends WordPressTestCase
{
    private function claims(
        string $email = 'user@example.test',
        string $sub = 'pin:abc',
        string $first = '',
        string $last = '',
    ): Claims {
        return new Claims(email: $email, sub: $sub, firstName: $first, lastName: $last);
    }

    public function test_finds_an_existing_user_by_subject(): void
    {
        $existing = WpState::addUser('user@example.test', 'pin:abc');

        $found = UserManager::findOrCreate($this->claims());

        $this->assertSame($existing->ID, $found->ID);
        $this->assertCount(1, WpState::$users, 'must not have created a duplicate');
    }

    public function test_matches_on_subject_even_after_the_email_changed_at_the_provider(): void
    {
        // This is why sub is checked first: the account follows the person, not the address.
        $existing = WpState::addUser('old@example.test', 'pin:abc');

        $found = UserManager::findOrCreate($this->claims(email: 'new@example.test'));

        $this->assertSame($existing->ID, $found->ID);
        $this->assertSame('new@example.test', $found->user_email, 'the address should be synced');
        $this->assertCount(1, WpState::$users);
    }

    public function test_adopts_a_pre_existing_account_by_email_and_backfills_the_subject(): void
    {
        // A site that had users before SSO: they must keep their account on first federated login,
        // and be keyed by sub from then on.
        $legacy = WpState::addUser('user@example.test');

        $found = UserManager::findOrCreate($this->claims());

        $this->assertSame($legacy->ID, $found->ID);
        $this->assertSame('pin:abc', WpState::metaFor($legacy->ID)['jwt_auth_sub'] ?? null);
        $this->assertCount(1, WpState::$users);
    }

    public function test_creates_a_new_user_when_nothing_matches(): void
    {
        $found = UserManager::findOrCreate($this->claims(first: 'Ada', last: 'Lovelace'));

        $this->assertCount(1, WpState::$users);
        $this->assertSame('user@example.test', $found->user_email);
        $this->assertSame('Ada', $found->first_name);
        $this->assertSame('Lovelace', $found->last_name);
        $this->assertSame('Ada Lovelace', $found->display_name);
        $this->assertSame('subscriber', $found->role, 'the default role, not an elevated one');
        $this->assertSame('pin:abc', WpState::metaFor($found->ID)['jwt_auth_sub'] ?? null);
    }

    public function test_never_grants_more_than_the_configured_default_role(): void
    {
        // A provider claim must never be able to talk the plugin into creating an administrator.
        $found = UserManager::findOrCreate($this->claims(email: 'admin@example.test'));

        $this->assertSame('subscriber', $found->role);
    }

    public function test_recovers_when_a_concurrent_request_creates_the_user_first(): void
    {
        // Two simultaneous logins for a brand-new user: one insert wins, the other must adopt it
        // rather than surfacing a fatal.
        WpState::$failNextCreateUser = true;

        $found = UserManager::findOrCreate($this->claims());

        $this->assertSame('user@example.test', $found->user_email);
        $this->assertCount(1, WpState::$users);
    }

    // ---------------------------------------------------------------------
    // Registration closed
    // ---------------------------------------------------------------------

    public function test_creates_nothing_when_the_site_is_not_accepting_registrations(): void
    {
        WpState::$usersCanRegister = false;

        $this->assertNull(UserManager::findOrCreate($this->claims()));
        $this->assertSame([], WpState::$users);
    }

    public function test_a_known_subject_still_signs_in_when_registration_is_closed(): void
    {
        // Closing registration turns away strangers, not the people who already have accounts.
        WpState::$usersCanRegister = false;
        $existing = WpState::addUser('user@example.test', 'pin:abc');

        $found = UserManager::findOrCreate($this->claims());

        $this->assertSame($existing->ID, $found?->ID);
    }

    public function test_still_adopts_a_pre_existing_account_by_email_when_registration_is_closed(): void
    {
        // Adopting an account the site already chose to create is a link, not a signup, so the
        // membership setting has no say in it.
        WpState::$usersCanRegister = false;
        $legacy = WpState::addUser('user@example.test');

        $found = UserManager::findOrCreate($this->claims());

        $this->assertSame($legacy->ID, $found?->ID);
        $this->assertSame('pin:abc', WpState::metaFor($legacy->ID)['jwt_auth_sub'] ?? null);
        $this->assertCount(1, WpState::$users);
    }

    public function test_syncs_changed_names_on_every_login(): void
    {
        WpState::addUser('user@example.test', 'pin:abc', 'Ada', 'Lovelace');

        $found = UserManager::findOrCreate(
            $this->claims(first: 'Augusta', last: 'King'),
        );

        $this->assertSame('Augusta', $found->first_name);
        $this->assertSame('King', $found->last_name);
        $this->assertSame('Augusta King', $found->display_name);
    }

    public function test_leaves_an_unchanged_profile_alone(): void
    {
        $existing = WpState::addUser('user@example.test', 'pin:abc', 'Ada', 'Lovelace');
        $before = clone $existing;

        $found = UserManager::findOrCreate($this->claims(first: 'Ada', last: 'Lovelace'));

        $this->assertSame($before->first_name, $found->first_name);
        $this->assertSame($before->user_email, $found->user_email);
    }
}
