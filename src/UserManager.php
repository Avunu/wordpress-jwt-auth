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
     *  3. Create a new user — only while the site is accepting registrations.
     *
     * Returns null when nothing matched and registration is closed. Note that step 2 keeps working
     * either way: adopting an account the site already decided to create is a link, not a signup.
     */
    public static function findOrCreate(Claims $claims): ?\WP_User
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

        // 2. Look up by email — but only if the provider stands behind the address.
        //
        // This branch hands over an existing account, with whatever roles it already has, on the
        // strength of an asserted address. On an IdP with self-service signup, an attacker who
        // registers with the victim's address and never confirms it would otherwise be grafted
        // straight onto the victim's WordPress account. The subject branch above is unaffected:
        // that binding was established by a previous successful sign-in.
        $user = get_user_by('email', $claims->email);
        if ($user instanceof \WP_User) {
            if (!$claims->emailIsAdoptable()) {
                return null;
            }
            update_user_meta($user->ID, 'jwt_auth_sub', $claims->sub);
            self::syncProfile($user, $claims);
            return $user;
        }

        if (!Registration::isOpen()) {
            return null;
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

    /**
     * Set while this class is writing to a user, so forgetSubOnEmailChange() can tell an
     * administrator re-keying an account apart from our own provider sync.
     */
    private static bool $syncing = false;

    /**
     * Drop the provider binding when somebody else changes a user's email address.
     *
     * `jwt_auth_sub` is checked before the email precisely so an account survives an address change
     * at the provider. The cost is that the binding is authoritative and never expires — and with
     * this provider the subject is a pure function of the address (`pin:sha256(email)`), so the
     * stored value keeps pointing at whatever address the user signed in with *last*.
     *
     * That inverts the meaning of the most security-sensitive edit an administrator can make. Change
     * a compromised user's email to cut off the attacker, and the old address still matches by
     * subject: the attacker signs in, lands in the account with all its roles, and the sync writes
     * the old address back over the new one. Forgetting the binding makes the change do what the
     * administrator plainly meant — the next sign-in has to match the new address, and re-keys.
     *
     * Providers with opaque subjects are unaffected: they simply re-key on the next sign-in too.
     */
    public static function forgetSubOnEmailChange(int $userId, mixed $oldUserData): void
    {
        if (self::$syncing) {
            return; // our own provider sync, which is the case this must not undo
        }

        $current = get_user_by('ID', $userId);
        if (!$current instanceof \WP_User || !$oldUserData instanceof \WP_User) {
            return;
        }
        if ($current->user_email === $oldUserData->user_email) {
            return;
        }

        delete_user_meta($userId, 'jwt_auth_sub');
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
            self::$syncing = true;
            try {
                wp_update_user($updates);
            } finally {
                self::$syncing = false;
            }
        }
    }
}
