<?php

declare(strict_types=1);

// Constants WordPress (and its environment) define at runtime that are not part
// of php-stubs/wordpress-stubs. WP_CLI / DOING_CRON are declared here so PHPStan
// knows they exist; their values are marked dynamic in phpstan.neon.dist so the
// `defined(...) && CONST` guards are not collapsed to always-true/false.
define('WPINC', 'wp-includes');

if (!defined('WP_CLI')) {
    define('WP_CLI', false);
}

if (!defined('DOING_CRON')) {
    define('DOING_CRON', false);
}
