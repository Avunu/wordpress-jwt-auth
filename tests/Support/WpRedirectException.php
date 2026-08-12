<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Support;

/** Thrown by the wp_redirect()/wp_safe_redirect() fakes, which the plugin always follows with exit. */
final class WpRedirectException extends \RuntimeException
{
    public function __construct(
        public readonly string $location,
        public readonly bool $safe,
    ) {
        parent::__construct("redirect to {$location}");
    }

    /**
     * The redirect target's query parameters, decoded.
     *
     * @return array<string, string>
     */
    public function query(): array
    {
        parse_str((string) parse_url($this->location, PHP_URL_QUERY), $params);
        /** @var array<string, string> $params */
        return $params;
    }
}
