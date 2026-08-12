<?php

declare(strict_types=1);

namespace JwtAuth\Tests\Support;

/**
 * The in-memory world the plugin runs against, reset between tests.
 *
 * Deliberately a fake rather than a mock: the plugin's interesting behaviour is *stateful* — a
 * single-use state transient, a JWKS cache refreshed exactly once on a signature failure, a user
 * looked up by sub and then by email. Real state lets a test assert what actually happened ("the
 * transient is gone", "user 2 got the auth cookie") instead of asserting that some function was
 * called, which is a much weaker claim.
 */
final class WpState
{
    /** @var array<string, mixed> */
    public static array $transients = [];

    /** @var array<int, \WP_User> */
    public static array $users = [];

    /** @var array<int, array<string, mixed>> user id => meta */
    public static array $userMeta = [];

    /**
     * URL => response array, or a callable(string $url, array $args): mixed for per-call behaviour.
     *
     * @var array<string, mixed>
     */
    public static array $httpResponses = [];

    /** @var list<array{method: string, url: string, args: array<string, mixed>}> */
    public static array $httpCalls = [];

    /** @var list<array{id: int, remember: bool}> */
    public static array $authCookies = [];

    /** @var list<array{hook: string, args: list<mixed>}> */
    public static array $actions = [];

    /** @var list<array{handle: string, data: array<string, mixed>}> */
    public static array $localizedScripts = [];

    /** @var list<string> */
    public static array $enqueuedScripts = [];

    public static int $currentUserId = 0;
    public static bool $loggedIn = false;
    public static bool $authCookieCleared = false;
    public static bool $doingCron = false;

    // WooCommerce page context.
    public static bool $isAccountPage = false;
    public static bool $isCheckout = false;

    /** Force the next wp_create_user() to fail, exercising the race-condition branch. */
    public static bool $failNextCreateUser = false;

    private static int $nextUserId = 1;

    public static function reset(): void
    {
        self::$transients = [];
        self::$users = [];
        self::$userMeta = [];
        self::$httpResponses = [];
        self::$httpCalls = [];
        self::$authCookies = [];
        self::$actions = [];
        self::$localizedScripts = [];
        self::$enqueuedScripts = [];
        self::$currentUserId = 0;
        self::$loggedIn = false;
        self::$authCookieCleared = false;
        self::$doingCron = false;
        self::$isAccountPage = false;
        self::$isCheckout = false;
        self::$failNextCreateUser = false;
        self::$nextUserId = 1;
    }

    public static function addUser(
        string $email,
        ?string $sub = null,
        string $first = '',
        string $last = '',
    ): \WP_User {
        $user = new \WP_User();
        $user->ID = self::$nextUserId++;
        $user->user_email = $email;
        $user->user_login = $email;
        $user->first_name = $first;
        $user->last_name = $last;
        $user->display_name = trim("{$first} {$last}") ?: $email;
        self::$users[$user->ID] = $user;
        if ($sub !== null) {
            self::$userMeta[$user->ID]['jwt_auth_sub'] = $sub;
        }
        return $user;
    }

    /** Register a JSON body to be returned for a URL. */
    public static function respondJson(string $url, mixed $payload, int $status = 200): void
    {
        self::$httpResponses[$url] = ['body' => json_encode($payload), 'status' => $status];
    }

    /** @return array<string, mixed>|null the meta bag for a user */
    public static function metaFor(int $userId): ?array
    {
        return self::$userMeta[$userId] ?? null;
    }
}
