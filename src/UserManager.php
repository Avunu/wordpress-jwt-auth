<?php

declare(strict_types=1);

namespace JwtAuth;

final class UserManager
{
    /**
     * Returns an existing WordPress user or creates one from the JWT claims.
     *
     * Lookup order:
     *  1. User whose jwt_auth_sub meta matches the subject claim (handles email changes).
     *  2. User whose email matches the email claim.
     *  3. Create a new user.
     */
    public static function findOrCreate(Claims $claims): \WP_User
    {
        // 1. Look up by sub
        $users = get_users([
            'meta_key'   => 'jwt_auth_sub',
            'meta_value' => $claims->sub,
            'number'     => 1,
        ]);

        if (!empty($users)) {
            self::syncProfile($users[0], $claims);
            return $users[0];
        }

        // 2. Look up by email
        $user = get_user_by('email', $claims->email);
        if ($user instanceof \WP_User) {
            update_user_meta($user->ID, 'jwt_auth_sub', $claims->sub);
            self::syncProfile($user, $claims);
            return $user;
        }

        return self::create($claims);
    }

    private static function create(Claims $claims): \WP_User
    {
        $userId = wp_create_user(
            $claims->email,
            wp_generate_password(32, special_chars: false),
            $claims->email,
        );

        if (is_wp_error($userId)) {
            // Race condition: another request created the user between our lookup and insert
            $user = get_user_by('email', $claims->email);
            if ($user instanceof \WP_User) return $user;
            throw new \RuntimeException('Failed to create user: ' . $userId->get_error_message());
        }

        wp_update_user([
            'ID'           => $userId,
            'first_name'   => $claims->firstName,
            'last_name'    => $claims->lastName,
            'display_name' => $claims->fullName(),
            'role'         => Config::defaultRole(),
        ]);

        update_user_meta($userId, 'jwt_auth_sub', $claims->sub);

        $user = get_user_by('ID', $userId);
        if (!$user instanceof \WP_User) {
            throw new \RuntimeException('Failed to load the newly-created user.');
        }

        return $user;
    }

    /** Keeps display name and email in sync with the provider on every login. */
    private static function syncProfile(\WP_User $user, Claims $claims): void
    {
        $updates = ['ID' => $user->ID];

        if ($claims->firstName !== '' && $user->first_name !== $claims->firstName) {
            $updates['first_name'] = $claims->firstName;
        }
        if ($claims->lastName !== '' && $user->last_name !== $claims->lastName) {
            $updates['last_name'] = $claims->lastName;
        }
        if ($claims->email !== '' && $user->user_email !== $claims->email) {
            $updates['user_email'] = $claims->email;
        }
        $fullName = $claims->fullName();
        if ($fullName !== '' && $user->display_name !== $fullName) {
            $updates['display_name'] = $fullName;
        }

        if (count($updates) > 1) {
            wp_update_user($updates);
        }
    }
}
