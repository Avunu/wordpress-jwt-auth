<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Unit;

use JwtAuth\Claims;
use JwtAuth\Tests\Support\WordPressTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Claims::class)]
final class ClaimsTest extends WordPressTestCase
{
    public function test_builds_from_a_standard_oidc_payload(): void
    {
        $claims = Claims::fromPayload((object) [
            'email' => 'user@example.test',
            'sub' => 'pin:abc',
            'given_name' => 'Ada',
            'family_name' => 'Lovelace',
            'name' => 'Ada Lovelace',
            'iss' => self::ISSUER,
            'aud' => self::CLIENT_ID,
        ]);

        $this->assertSame('user@example.test', $claims->email);
        $this->assertSame('pin:abc', $claims->sub);
        $this->assertSame('Ada', $claims->firstName);
        $this->assertSame('Lovelace', $claims->lastName);
        $this->assertSame('Ada Lovelace', $claims->fullName());
    }

    public function test_falls_back_to_the_email_when_the_payload_has_no_subject(): void
    {
        // sub is what user records are keyed on, so it must never be empty.
        $claims = Claims::fromPayload((object) ['email' => 'user@example.test']);

        $this->assertSame('user@example.test', $claims->sub);
    }

    public function test_rejects_a_payload_with_no_email(): void
    {
        // Without an email there is no way to find or create a WordPress account.
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('missing required email claim');

        Claims::fromPayload((object) ['sub' => 'pin:abc']);
    }

    public function test_full_name_prefers_the_name_parts_and_falls_back_to_display_name(): void
    {
        $parts = new Claims(email: 'a@b.test', sub: 's', firstName: 'Ada', lastName: 'Lovelace');
        $this->assertSame('Ada Lovelace', $parts->fullName());

        $firstOnly = new Claims(email: 'a@b.test', sub: 's', firstName: 'Ada');
        $this->assertSame('Ada', $firstOnly->fullName());

        $displayOnly = new Claims(email: 'a@b.test', sub: 's', displayName: 'Ada L.');
        $this->assertSame('Ada L.', $displayOnly->fullName());

        $nothing = new Claims(email: 'a@b.test', sub: 's');
        $this->assertSame('', $nothing->fullName());
    }

    public function test_matches_an_audience_given_as_a_string_or_a_list(): void
    {
        // OIDC allows `aud` to be either, and the whole tenant separation rests on this check.
        $single = new Claims(email: 'a@b.test', sub: 's', aud: 'testclient');
        $this->assertTrue($single->hasAudience('testclient'));
        $this->assertFalse($single->hasAudience('otherclient'));

        $many = new Claims(email: 'a@b.test', sub: 's', aud: ['testclient', 'otherclient']);
        $this->assertTrue($many->hasAudience('testclient'));
        $this->assertTrue($many->hasAudience('otherclient'));
        $this->assertFalse($many->hasAudience('thirdclient'));
    }

    public function test_audience_matching_is_strict(): void
    {
        // A loose comparison would let 0 == 'testclient' through on some PHP versions.
        $claims = new Claims(email: 'a@b.test', sub: 's', aud: ['testclient']);

        $this->assertFalse($claims->hasAudience(''));
        $this->assertFalse($claims->hasAudience('TESTCLIENT'));
    }

    // ---------------------------------------------------------------------
    // email_verified
    // ---------------------------------------------------------------------

    public function test_distinguishes_an_unverified_address_from_an_unstated_one(): void
    {
        // Three states, not two. Collapsing absent into false would break every provider that
        // omits the claim; collapsing it into true would discard the warning when one says false.
        $verified = Claims::fromPayload((object) ['email' => 'a@b.test', 'email_verified' => true]);
        $unverified = Claims::fromPayload((object) ['email' => 'a@b.test', 'email_verified' => false]);
        $unstated = Claims::fromPayload((object) ['email' => 'a@b.test']);

        $this->assertTrue($verified->emailVerified);
        $this->assertFalse($unverified->emailVerified);
        $this->assertNull($unstated->emailVerified);
    }

    public function test_accepts_the_claim_as_a_string_as_some_providers_send_it(): void
    {
        $stringTrue = Claims::fromPayload((object) [
            'email' => 'a@b.test',
            'email_verified' => 'true',
        ]);
        $stringFalse = Claims::fromPayload((object) [
            'email' => 'a@b.test',
            'email_verified' => 'false',
        ]);

        $this->assertTrue($stringTrue->emailVerified);
        $this->assertFalse($stringFalse->emailVerified);
    }

    public function test_treats_an_unrecognised_value_as_unstated_rather_than_verified(): void
    {
        // Anything we cannot read confidently must not be allowed to read as a positive assertion.
        $claims = Claims::fromPayload((object) ['email' => 'a@b.test', 'email_verified' => 'yes']);

        $this->assertNull($claims->emailVerified);
    }

    public function test_an_explicitly_unverified_address_is_never_adoptable(): void
    {
        $claims = new Claims(email: 'a@b.test', sub: 's', emailVerified: false);

        $this->assertFalse($claims->emailIsAdoptable());
    }

    public function test_an_unstated_address_is_adoptable_by_default(): void
    {
        $claims = new Claims(email: 'a@b.test', sub: 's', emailVerified: null);

        $this->assertTrue($claims->emailIsAdoptable());
    }
}
