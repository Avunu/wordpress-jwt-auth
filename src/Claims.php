<?php

declare(strict_types=1);

namespace JwtAuth;

final class Claims
{
    /**
     * @param list<string>|string $aud
     */
    public function __construct(
        public readonly string $email,
        public readonly string $sub,
        public readonly string $firstName = '',
        public readonly string $lastName = '',
        public readonly string $displayName = '',
        public readonly string $iss = '',
        public readonly string|array $aud = '',
        /**
         * OIDC `email_verified`. Null when the provider omitted it, which is not the same as false
         * and must not be treated as such — see UserManager::findOrCreate(), where the difference
         * decides whether an existing WordPress account may be adopted by email.
         */
        public readonly ?bool $emailVerified = null,
    ) {}

    /**
     * Whether this address may be used to claim an EXISTING WordPress account.
     *
     * The subject is the account key; the email is only a fallback for adopting accounts that
     * predate SSO. That fallback is the dangerous one — it hands over an account, with whatever
     * roles it has, on the strength of an address the provider asserted. An address the provider
     * explicitly says it has not verified is worth nothing here: on any IdP with self-service
     * signup, anyone can assert somebody else's.
     *
     * Absent is deliberately not treated as false. The companion worker never issues an
     * unverified address — a PIN or magic link had to be read at it — and older tokens predate the
     * claim entirely. Sites whose provider may assert unverified addresses can set
     * JWT_AUTH_REQUIRE_VERIFIED_EMAIL to demand it positively.
     */
    public function emailIsAdoptable(): bool
    {
        if ($this->emailVerified === false) {
            return false;
        }
        return $this->emailVerified === true || !Config::requireVerifiedEmail();
    }

    public function fullName(): string
    {
        return trim("{$this->firstName} {$this->lastName}") ?: $this->displayName;
    }

    public function hasAudience(string $expected): bool
    {
        $aud = is_array($this->aud) ? $this->aud : [$this->aud];
        return in_array($expected, $aud, strict: true);
    }

    public static function fromPayload(object $payload): self
    {
        $email = $payload->{Config::claimEmail()}
            ?? throw new \UnexpectedValueException('JWT missing required email claim');

        return new self(
            email: $email,
            sub: $payload->sub ?? $email,
            firstName: $payload->{Config::claimFirstName()} ?? '',
            lastName: $payload->{Config::claimLastName()} ?? '',
            displayName: $payload->{Config::claimName()} ?? '',
            iss: $payload->iss ?? '',
            aud: $payload->aud ?? '',
            // Providers send this as a real boolean, but some send the strings "true"/"false";
            // anything unrecognised is treated as absent rather than guessed at.
            emailVerified: match (true) {
                !property_exists($payload, 'email_verified') => null,
                $payload->email_verified === true, $payload->email_verified === 'true' => true,
                $payload->email_verified === false, $payload->email_verified === 'false' => false,
                default => null,
            },
        );
    }
}
