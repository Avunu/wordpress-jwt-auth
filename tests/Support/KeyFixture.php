<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Support;

use Firebase\JWT\JWT;

/**
 * Real RSA keys and real signatures — no stubbing of the crypto layer.
 *
 * The point of the Validator tests is that a *forged* token is rejected, and you cannot demonstrate
 * that against a fake signer. Keys are generated once per process and reused, since 2048-bit
 * generation is the slowest thing in the suite.
 */
final class KeyFixture
{
    private static ?self $primary = null;
    private static ?self $rotated = null;

    private function __construct(
        public readonly string $privatePem,
        public readonly string $publicPem,
        public readonly string $kid,
        private readonly string $modulus,
        private readonly string $exponent,
    ) {}

    public static function primary(): self
    {
        return self::$primary ??= self::generate('test-key-1');
    }

    /** A second, unrelated key — used to prove a token signed by the wrong key is refused. */
    public static function rotated(): self
    {
        return self::$rotated ??= self::generate('test-key-2');
    }

    private static function generate(string $kid): self
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($resource === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }
        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new \RuntimeException('openssl_pkey_get_details failed');
        }

        return new self(
            privatePem: (string) $privatePem,
            publicPem: (string) $details['key'],
            kid: $kid,
            modulus: self::base64url($details['rsa']['n']),
            exponent: self::base64url($details['rsa']['e']),
        );
    }

    /** This key as a single JWK, shaped exactly like the worker's /.well-known/jwks.json entry. */
    public function jwk(): array
    {
        return [
            'kty' => 'RSA',
            'n' => $this->modulus,
            'e' => $this->exponent,
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => $this->kid,
        ];
    }

    /** @param list<self> $keys */
    public static function jwks(array $keys): array
    {
        return ['keys' => array_map(static fn (self $k): array => $k->jwk(), $keys)];
    }

    /**
     * Mint a genuinely signed RS256 token. Claims default to a valid, unexpired identity so each
     * test only has to state the one thing it is varying.
     *
     * @param array<string, mixed> $claims
     */
    public function sign(array $claims = []): string
    {
        $now = time();
        $payload = array_merge([
            'iss' => 'https://auth.test',
            'aud' => 'testclient',
            'sub' => 'pin:abc123',
            'email' => 'user@example.test',
            'iat' => $now,
            'exp' => $now + 300,
        ], $claims);

        return JWT::encode($payload, $this->privatePem, 'RS256', $this->kid);
    }

    /**
     * An unsigned `alg: none` token. php-jwt will not produce one, so it is assembled by hand —
     * which is precisely how an attacker would present it.
     *
     * @param array<string, mixed> $claims
     */
    public function unsignedNoneToken(array $claims = []): string
    {
        $now = time();
        $payload = array_merge([
            'iss' => 'https://auth.test',
            'aud' => 'testclient',
            'sub' => 'pin:attacker',
            'email' => 'attacker@evil.test',
            'iat' => $now,
            'exp' => $now + 300,
        ], $claims);

        // Carries a real kid, so key lookup succeeds and the rejection has to come from the
        // algorithm check itself rather than from failing to find a key.
        $header = self::base64url(
            (string) json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => $this->kid]),
        );
        $body = self::base64url((string) json_encode($payload));
        return "{$header}.{$body}.";
    }

    /**
     * The classic algorithm-confusion forgery: sign with HMAC, using the RSA *public* key as the
     * shared secret. A verifier that trusts the header's `alg` over its own key metadata accepts it,
     * because the public key is, by definition, public.
     *
     * @param array<string, mixed> $claims
     */
    public function hmacForgedToken(array $claims = []): string
    {
        $now = time();
        $payload = array_merge([
            'iss' => 'https://auth.test',
            'aud' => 'testclient',
            'sub' => 'pin:attacker',
            'email' => 'attacker@evil.test',
            'iat' => $now,
            'exp' => $now + 300,
        ], $claims);

        return JWT::encode($payload, $this->publicPem, 'HS256', $this->kid);
    }

    private static function base64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
