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
    ) {}

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
        );
    }
}
