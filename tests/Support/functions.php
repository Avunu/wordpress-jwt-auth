<?php

declare(strict_types=1);

// The slice of WordPress this plugin touches, implemented against WpState. Global scope on purpose:
// the plugin calls these as plain functions, so that is how they must be defined.

use JwtAuth\Tests\Support\WpDieException;
use JwtAuth\Tests\Support\WpRedirectException;
use JwtAuth\Tests\Support\WpState;

// ---------------------------------------------------------------------------
// Classes
// ---------------------------------------------------------------------------

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        /** @param array<string, mixed> $data */
        public function __construct(
            private string $code = '',
            private string $message = '',
            private array $data = [],
        ) {}

        public function get_error_code(): string
        {
            return $this->code;
        }

        public function get_error_message(): string
        {
            return $this->message;
        }
    }
}

if (!class_exists('WP_User')) {
    class WP_User
    {
        public int $ID = 0;
        public string $user_email = '';
        public string $user_login = '';
        public string $first_name = '';
        public string $last_name = '';
        public string $display_name = '';
        public string $role = '';
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

defined('DAY_IN_SECONDS') || define('DAY_IN_SECONDS', 86400);
defined('HOUR_IN_SECONDS') || define('HOUR_IN_SECONDS', 3600);
defined('MINUTE_IN_SECONDS') || define('MINUTE_IN_SECONDS', 60);

// ---------------------------------------------------------------------------
// Transients
// ---------------------------------------------------------------------------

function get_transient(string $key): mixed
{
    return WpState::$transients[$key] ?? false;
}

function set_transient(string $key, mixed $value, int $ttl = 0): bool
{
    WpState::$transients[$key] = $value;
    return true;
}

function delete_transient(string $key): bool
{
    unset(WpState::$transients[$key]);
    return true;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/** @param array<string, mixed> $args */
function jwt_auth_test_http(string $method, string $url, array $args): mixed
{
    WpState::$httpCalls[] = ['method' => $method, 'url' => $url, 'args' => $args];

    $response = WpState::$httpResponses[$url]
        ?? new WP_Error('http_request_failed', "No test response registered for {$url}");

    // A callable lets a test vary the response per call.
    return is_callable($response) ? $response($url, $args) : $response;
}

/** @param array<string, mixed> $args */
function wp_remote_get(string $url, array $args = []): mixed
{
    return jwt_auth_test_http('GET', $url, $args);
}

/** @param array<string, mixed> $args */
function wp_remote_post(string $url, array $args = []): mixed
{
    return jwt_auth_test_http('POST', $url, $args);
}

function is_wp_error(mixed $thing): bool
{
    return $thing instanceof WP_Error;
}

function wp_remote_retrieve_body(mixed $response): string
{
    return is_array($response) ? (string) ($response['body'] ?? '') : '';
}

// ---------------------------------------------------------------------------
// Redirects / termination
// ---------------------------------------------------------------------------

function wp_redirect(string $location, int $status = 302): never
{
    throw new WpRedirectException($location, safe: false);
}

function wp_safe_redirect(string $location, int $status = 302): never
{
    throw new WpRedirectException($location, safe: true);
}

function wp_validate_redirect(string $location, string $fallback = ''): string
{
    // WordPress permits only same-host redirects; anything else falls back.
    $host = parse_url($location, PHP_URL_HOST);
    if ($host === null || $host === false || $host === 'example.test') {
        return $location;
    }
    return $fallback;
}

/** @param array<string, mixed> $args */
function wp_die(string $message = '', string $title = '', array $args = []): never
{
    throw new WpDieException($message, $title, $args);
}

// ---------------------------------------------------------------------------
// URLs / escaping
// ---------------------------------------------------------------------------

function home_url(string $path = '/'): string
{
    return 'https://example.test' . ($path === '' ? '/' : $path);
}

function wp_login_url(string $redirect = ''): string
{
    $url = 'https://example.test/wp-login.php';
    return $redirect === '' ? $url : $url . '?redirect_to=' . rawurlencode($redirect);
}

function add_query_arg(string $key, string $value, string $url): string
{
    $separator = str_contains($url, '?') ? '&' : '?';
    return $url . $separator . $key . '=' . $value;
}

function sanitize_url(string $url): string
{
    return filter_var($url, FILTER_SANITIZE_URL) ?: '';
}

function sanitize_text_field(string $value): string
{
    return trim(strip_tags($value));
}

function esc_url(string $url): string
{
    return htmlspecialchars($url, ENT_QUOTES);
}

function esc_html(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES);
}

function plugin_dir_url(string $file): string
{
    return 'https://example.test/wp-content/plugins/jwt-auth/';
}

// ---------------------------------------------------------------------------
// Auth / session
// ---------------------------------------------------------------------------

function is_user_logged_in(): bool
{
    return WpState::$loggedIn;
}

function wp_clear_auth_cookie(): void
{
    WpState::$authCookieCleared = true;
}

function wp_set_current_user(int $id): void
{
    WpState::$currentUserId = $id;
}

function wp_set_auth_cookie(int $id, bool $remember = false): void
{
    WpState::$authCookies[] = ['id' => $id, 'remember' => $remember];
    WpState::$loggedIn = true;
}

function wp_doing_cron(): bool
{
    return WpState::$doingCron;
}

function do_action(string $hook, mixed ...$args): void
{
    WpState::$actions[] = ['hook' => $hook, 'args' => $args];
}

function wp_generate_password(int $length = 12, bool $special_chars = true): string
{
    return substr(str_repeat('aB3', (int) ceil($length / 3)), 0, $length);
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/**
 * Supports the meta_key/meta_value lookup UserManager performs.
 *
 * @param array<string, mixed> $args
 * @return list<WP_User>
 */
function get_users(array $args = []): array
{
    $key = $args['meta_key'] ?? null;
    if ($key === null) {
        return array_values(WpState::$users);
    }
    $value = $args['meta_value'] ?? null;

    $found = [];
    foreach (WpState::$users as $id => $user) {
        if ((WpState::$userMeta[$id][$key] ?? null) === $value) {
            $found[] = $user;
        }
    }
    $limit = $args['number'] ?? null;
    return is_int($limit) ? array_slice($found, 0, $limit) : $found;
}

function get_user_by(string $field, mixed $value): WP_User|false
{
    foreach (WpState::$users as $user) {
        $match = match ($field) {
            'email' => $user->user_email === $value,
            'ID', 'id' => $user->ID === (int) $value,
            'login' => $user->user_login === $value,
            default => false,
        };
        if ($match) {
            return $user;
        }
    }
    return false;
}

function wp_create_user(string $login, string $password, string $email = ''): int|WP_Error
{
    $address = $email !== '' ? $email : $login;

    if (WpState::$failNextCreateUser) {
        // Model the real race the plugin guards against: a concurrent request won the insert, so
        // the row now exists *and* our own create fails. A test that only returned the error would
        // not exercise the recovery lookup that follows.
        WpState::$failNextCreateUser = false;
        WpState::addUser($address);
        return new WP_Error('existing_user_email', 'Sorry, that email address is already used!');
    }

    return WpState::addUser($address)->ID;
}

/** @param array<string, mixed> $data */
function wp_update_user(array $data): int|WP_Error
{
    $id = (int) ($data['ID'] ?? 0);
    $user = WpState::$users[$id] ?? null;
    if ($user === null) {
        return new WP_Error('invalid_user_id', 'Invalid user ID.');
    }
    foreach (['first_name', 'last_name', 'display_name', 'user_email', 'role'] as $field) {
        if (isset($data[$field])) {
            $user->{$field} = (string) $data[$field];
        }
    }
    return $id;
}

function update_user_meta(int $id, string $key, mixed $value): bool
{
    WpState::$userMeta[$id][$key] = $value;
    return true;
}

// ---------------------------------------------------------------------------
// WooCommerce
// ---------------------------------------------------------------------------

function is_account_page(): bool
{
    return WpState::$isAccountPage;
}

function is_checkout(): bool
{
    return WpState::$isCheckout;
}

function wc_get_page_permalink(string $page): string
{
    return 'https://example.test/my-account/';
}

function wc_get_checkout_url(): string
{
    return 'https://example.test/checkout/';
}

/**
 * @param list<string> $deps
 * @param array<string, mixed>|bool $args
 */
function wp_enqueue_script(
    string $handle,
    string $src = '',
    array $deps = [],
    string|bool|null $ver = false,
    array|bool $args = false,
): void {
    WpState::$enqueuedScripts[] = $handle;
}

/** @param array<string, mixed> $data */
function wp_localize_script(string $handle, string $name, array $data): bool
{
    WpState::$localizedScripts[] = ['handle' => $handle, 'data' => $data];
    return true;
}
