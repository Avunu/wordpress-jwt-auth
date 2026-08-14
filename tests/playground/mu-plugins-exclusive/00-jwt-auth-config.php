<?php

/**
 * Test-only. The same site as tests/playground/mu-plugins, with JWT_AUTH_EXCLUSIVE turned on.
 *
 * A separate directory rather than a flag, because constants are the plugin's configuration surface
 * and PHP cannot redefine one: a suite that needs exclusive mode has to be a differently-booted
 * server, not a differently-configured request. bootPlayground({ muPlugins: 'mu-plugins-exclusive' })
 * mounts this one instead.
 *
 * The shared file is required rather than copied so the base configuration has exactly one
 * definition; it is reachable because the repo root is mounted as the plugin directory.
 */

declare(strict_types=1);

defined('JWT_AUTH_EXCLUSIVE') || define('JWT_AUTH_EXCLUSIVE', true);

require_once __DIR__ . '/../plugins/jwt-auth/tests/playground/mu-plugins/00-jwt-auth-config.php';
