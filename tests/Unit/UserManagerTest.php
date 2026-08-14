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
        ?bool $emailVerified = null,
    ): Claims {
        return new Claims(
            email: $email,
            sub: $sub,
            firstName: $first,
            lastName: $last,
            emailVerified: $emailVerified,
        );
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
        $this->assertSame('subscriber', $found->role, 'the site default role, not an elevated one');
        $this->assertSame('pin:abc', WpState::metaFor($found->ID)['jwt_auth_sub'] ?? null);
    }

    public function test_gives_new_accounts_the_role_the_site_chose_for_new_users(): void
    {
        // Settings → General → "New User Default Role", the same setting every other registration
        // path obeys. The plugin does not read it: wp_create_user() applies it, and findOrCreate()
        // deliberately omits a 'role' key afterwards so nothing overwrites core's answer.
        WpState::$defaultRole = 'contributor';

        $found = UserManager::findOrCreate($this->claims());

        $this->assertSame('contributor', $found->role);
    }

    public function test_never_grants_more_than_the_site_default_role(): void
    {
        // A provider claim must never be able to talk the plugin into creating an administrator.
        // Deferring to core is what makes this true by construction rather than by vigilance —
        // there is no code path in which a claim reaches the role.
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
    // Adoption by email requires an address the provider stands behind
    // ---------------------------------------------------------------------

    public function test_refuses_to_hand_over_an_existing_account_on_an_unverified_address(): void
    {
        // The account-takeover this guards. On any IdP with self-service signup an attacker can
        // register with the victim's address and never confirm it; without this check the email
        // fallback grafts them straight onto the victim's WordPress account, roles and all.
        $victim = WpState::addUser('user@example.test');
        $victim->role = 'administrator';

        $found = UserManager::findOrCreate($this->claims(sub: 'pin:attacker', emailVerified: false));

        $this->assertNull($found, 'an explicitly unverified address must not claim an account');
        $this->assertArrayNotHasKey(
            'jwt_auth_sub',
            WpState::metaFor($victim->ID) ?? [],
            'and it must not leave the attacker bound to the account either',
        );
    }

    public function test_adopts_on_a_verified_address(): void
    {
        $legacy = WpState::addUser('user@example.test');

        $found = UserManager::findOrCreate($this->claims(emailVerified: true));

        $this->assertSame($legacy->ID, $found?->ID);
    }

    public function test_still_adopts_when_the_provider_omits_the_claim(): void
    {
        // Absent is not false. The companion worker never issues an address nobody read a PIN at,
        // and tokens minted before the claim existed must keep working — so the default stays
        // permissive, and sites with a riskier IdP opt in via JWT_AUTH_REQUIRE_VERIFIED_EMAIL.
        $legacy = WpState::addUser('user@example.test');

        $found = UserManager::findOrCreate($this->claims(emailVerified: null));

        $this->assertSame($legacy->ID, $found?->ID);
    }

    public function test_a_known_subject_signs_in_regardless_of_the_verified_flag(): void
    {
        // The subject binding was established by a previous successful sign-in, so it is evidence in
        // its own right. Only the email *fallback* rests on the provider's word about the address.
        $existing = WpState::addUser('user@example.test', 'pin:abc');

        $found = UserManager::findOrCreate($this->claims(emailVerified: false));

        $this->assertSame($existing->ID, $found?->ID);
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

    // ---------------------------------------------------------------------
    // A changed email must actually revoke the old address
    // ---------------------------------------------------------------------

    public function test_an_admin_changing_the_email_drops_the_stale_provider_binding(): void
    {
        // This provider derives the subject from the address, so the stored binding keeps pointing
        // at whatever address was used last. Without this, changing a compromised user's email —
        // the textbook remediation — leaves the attacker's old address matching by subject, with
        // all of the account's roles intact.
        $user = WpState::addUser('alice@old.example', 'pin:abc');
        $before = clone $user;
        $user->user_email = 'alice@new.example';

        UserManager::forgetSubOnEmailChange($user->ID, $before);

        $this->assertArrayNotHasKey('jwt_auth_sub', WpState::metaFor($user->ID) ?? []);
    }

    public function test_the_old_address_can_no_longer_take_over_the_account(): void
    {
        $alice = WpState::addUser('alice@old.example', 'pin:abc');
        $before = clone $alice;
        $alice->user_email = 'alice@new.example';
        UserManager::forgetSubOnEmailChange($alice->ID, $before);

        // The attacker still controls the old mailbox and signs in with it.
        $found = UserManager::findOrCreate($this->claims(email: 'alice@old.example', sub: 'pin:abc'));

        $this->assertNotSame($alice->ID, $found?->ID, 'must not land in Alice\'s account');
        $this->assertSame('alice@new.example', $alice->user_email, 'and must not rewrite her address');
    }

    public function test_an_unchanged_email_keeps_the_binding(): void
    {
        $user = WpState::addUser('alice@example.test', 'pin:abc');

        UserManager::forgetSubOnEmailChange($user->ID, clone $user);

        $this->assertSame('pin:abc', WpState::metaFor($user->ID)['jwt_auth_sub'] ?? null);
    }

    public function test_the_plugin_own_provider_sync_does_not_drop_the_binding(): void
    {
        // syncProfile writes the token's email back to the user, which fires profile_update. If that
        // undid the binding, every legitimate address change at the provider would de-key the
        // account and mint a fresh one on the next sign-in.
        $user = WpState::addUser('old@example.test', 'pin:abc');

        UserManager::findOrCreate($this->claims(email: 'new@example.test', sub: 'pin:abc'));

        $this->assertSame('new@example.test', $user->user_email);
        $this->assertSame('pin:abc', WpState::metaFor($user->ID)['jwt_auth_sub'] ?? null);
    }
}
