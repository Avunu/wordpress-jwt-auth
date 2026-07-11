<?php

declare(strict_types=1);

// Constants WordPress (and its environment) define at runtime that are not part
// of php-stubs/wordpress-stubs. WP_CLI is declared here so PHPStan knows it exists;
// its value is marked dynamic in phpstan.neon.dist so the `defined(...) && WP_CLI`
// guard is not collapsed to always-true/false.
define('WPINC', 'wp-includes');

if (!defined('WP_CLI')) {
    define('WP_CLI', false);
}
