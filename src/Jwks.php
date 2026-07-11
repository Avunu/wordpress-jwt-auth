<?php

declare(strict_types=1);

namespace JwtAuth;

final class Jwks
{
    private const TTL = 3600; // 1 hour

    /**
     * Returns the cached JWKS array, fetching from the URI on a miss.
     *
     * @return array<string, mixed>
     */
    public static function get(string $jwksUri): array
    {
        $cached = get_transient(self::key($jwksUri));
        return $cached !== false ? $cached : self::refresh($jwksUri);
    }

    /**
     * Forces a fresh fetch and updates the cache. Called on signature validation failure.
     *
     * @return array<string, mixed>
     */
    public static function refresh(string $jwksUri): array
    {
        $response = wp_remote_get($jwksUri, ['timeout' => 10]);

        if (is_wp_error($response)) {
            throw new \RuntimeException('JWKS fetch failed: ' . $response->get_error_message());
        }

        $jwks = json_decode(wp_remote_retrieve_body($response), associative: true);

        if (empty($jwks['keys'])) {
            throw new \RuntimeException('Invalid JWKS response from ' . $jwksUri);
        }

        set_transient(self::key($jwksUri), $jwks, self::TTL);
        return $jwks;
    }

    private static function key(string $jwksUri): string
    {
        return 'jwt_auth_jwks_' . md5($jwksUri);
    }
}
