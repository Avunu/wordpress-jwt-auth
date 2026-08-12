<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Support;

/**
 * WordPress terminates the request inside wp_die(), and the plugin follows it with `exit`. Neither
 * is catchable, so the fake throws instead. That turns "this request would have died with a 401"
 * into an assertion rather than a killed test process — the same trick WordPress core's own test
 * suite uses.
 */
final class WpDieException extends \RuntimeException
{
    /** @param array<string, mixed> $args */
    public function __construct(
        public readonly string $body,
        public readonly string $title,
        public readonly array $args,
    ) {
        parent::__construct($body);
    }

    public function status(): ?int
    {
        $response = $this->args['response'] ?? null;
        return is_int($response) ? $response : null;
    }
}
