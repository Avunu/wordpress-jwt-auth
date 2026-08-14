<?php

declare(strict_types=1);

// setcookie() is a PHP built-in, so it cannot be redeclared in the global namespace. The plugin
// calls it unqualified from `namespace JwtAuth`, and PHP resolves unqualified function calls to the
// current namespace before falling back to the global one — so declaring it here shadows the
// built-in for the plugin's code under test, and only there. In production this file does not
// exist, the lookup misses, and the real built-in runs.
//
// The state binder's attributes ARE the control: a cookie without HttpOnly, without Secure, or with
// the wrong lifetime is a materially different security story, so the fake records them for tests
// to assert on rather than discarding them.

namespace JwtAuth;

use JwtAuth\Tests\Support\WpState;

/** @param array<string, mixed> $options */
function setcookie(string $name, string $value = '', array $options = []): bool
{
    WpState::$cookiesSet[] = ['name' => $name, 'value' => $value, 'options' => $options];
    if ($value === '') {
        unset($_COOKIE[$name]);
    } else {
        $_COOKIE[$name] = $value;
    }
    return true;
}
