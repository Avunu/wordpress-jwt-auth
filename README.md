# JWT Auth

A WordPress plugin that completely replaces native authentication with an external JWT provider. All login attempts are redirected to the provider; users are created on demand with the `subscriber` role. No admin UI — configured entirely via `wp-config.php`.

Supports two modes:

| Mode | When to use | Examples |
|------|-------------|---------|
| **OIDC** | WordPress redirects users to the provider for login | Zitadel, Keycloak, Auth0, Okta |
| **Proxy** | An upstream proxy injects a signed JWT into every request | Cloudflare Zero Trust, Authentik, Traefik Forward Auth |

---

## Requirements

- PHP 8.4+
- WordPress 6.4+
- [Composer](https://getcomposer.org/)

---

## Installation

### Recommended: install the release zip

1. Download `jwt-auth.zip` from the [latest GitHub Release](https://github.com/Avunu/wordpress-jwt-auth/releases/latest)
2. In WordPress, go to **Plugins → Add New → Upload Plugin** and upload the zip
3. Configure the required constants in `wp-config.php` (see Configuration section)
4. Activate the plugin through the WordPress admin interface

The release zip bundles all Composer dependencies, so there is no separate `composer install`
step. Once installed, the plugin checks GitHub for new releases and offers one-click updates
through the normal WordPress Plugins screen.

### From source (development)

```bash
# 1. Place this directory inside wp-content/plugins/jwt-auth/
# 2. Install dependencies
composer install --no-dev --optimize-autoloader

# 3. Activate the plugin in wp-admin, or via WP-CLI:
wp plugin activate jwt-auth
```

A Nix devshell with PHP 8.4 and Composer is provided:

```bash
nix develop
```

---

## Configuration

All configuration is done via constants in `wp-config.php`. The plugin does nothing — and leaves WordPress fully functional — until at least one mode is configured.

### OIDC mode (Zitadel, Keycloak, Auth0, …)

Define `JWT_AUTH_CLIENT_ID` to activate. Endpoints are auto-discovered from `{issuer}/.well-known/openid-configuration`.

```php
define('JWT_AUTH_ISSUER',        'https://your.zitadel.cloud');
define('JWT_AUTH_CLIENT_ID',     'your-client-id@project');
define('JWT_AUTH_CLIENT_SECRET', ''); // leave empty for PKCE-only (recommended)
```

The plugin uses PKCE (S256) by default. Set `JWT_AUTH_CLIENT_SECRET` only if your provider requires a confidential client.

**Zitadel setup checklist:**
1. Create a PKCE application in your Zitadel project.
2. Set the allowed redirect URI to `https://yoursite.com/?jwt_auth_callback=1`.
3. Set the post-logout redirect URI to `https://yoursite.com/`.
4. Copy the issuer URL and client ID into `wp-config.php`.

---

### Proxy mode (Cloudflare Zero Trust, Authentik, …)

Define `JWT_AUTH_JWKS_URI` without `JWT_AUTH_CLIENT_ID` to activate. The proxy must inject a signed JWT into every authenticated request before it reaches WordPress.

```php
// Cloudflare Zero Trust
define('JWT_AUTH_ISSUER',       'https://yourteam.cloudflareaccess.com');
define('JWT_AUTH_JWKS_URI',     'https://yourteam.cloudflareaccess.com/cdn-cgi/access/certs');
define('JWT_AUTH_AUD',          'your-cf-audience-tag');
define('JWT_AUTH_TOKEN_COOKIE', 'CF_Authorization');

// Or use a header instead of a cookie:
// define('JWT_AUTH_TOKEN_HEADER', 'Cf-Access-Jwt-Assertion');
```

**Cloudflare Zero Trust setup checklist:**
1. Add a Cloudflare Access application protecting your WordPress site.
2. Copy the **Audience Tag** from the application settings into `JWT_AUTH_AUD`.
3. Set your team domain in `JWT_AUTH_ISSUER` and `JWT_AUTH_JWKS_URI` as shown above.

---

### All constants

| Constant | Default | Description |
|----------|---------|-------------|
| `JWT_AUTH_ISSUER` | — | Provider base URL. Used for `iss` claim validation and OIDC discovery. |
| `JWT_AUTH_CLIENT_ID` | — | OIDC client ID. **Presence of this constant activates OIDC mode.** |
| `JWT_AUTH_CLIENT_SECRET` | `''` | OIDC client secret. Leave empty for PKCE-only. |
| `JWT_AUTH_JWKS_URI` | — | JWKS endpoint URL. **Required in proxy mode.** Overrides OIDC-discovered URI when set in OIDC mode. |
| `JWT_AUTH_AUD` | — | Expected `aud` claim value. Required in proxy mode. Overrides `client_id` audience check in OIDC mode. |
| `JWT_AUTH_TOKEN_COOKIE` | — | Cookie name carrying the JWT (proxy mode). |
| `JWT_AUTH_TOKEN_HEADER` | — | HTTP header name carrying the JWT (proxy mode). Falls back to `Authorization: Bearer` if neither cookie nor header is configured. |
| `JWT_AUTH_LOGOUT_URL` | — | Provider logout URL. Overrides OIDC `end_session_endpoint` when set. |
| `JWT_AUTH_DEFAULT_ROLE` | `subscriber` | WordPress role assigned to newly created users. |
| `JWT_AUTH_CLAIM_EMAIL` | `email` | JWT claim containing the user's email address. |
| `JWT_AUTH_CLAIM_FIRST_NAME` | `given_name` | JWT claim for first name. |
| `JWT_AUTH_CLAIM_LAST_NAME` | `family_name` | JWT claim for last name. |
| `JWT_AUTH_CLAIM_NAME` | `name` | JWT claim for display name. |
| `JWT_AUTH_REDIRECT` | `/` | Post-login redirect destination. |
| `JWT_AUTH_PROVIDER_NAME` | `SSO` | Provider label shown in the WooCommerce sign-in button. |

---

## Behaviour

### Authentication flow (OIDC mode)

1. Any visit to `wp-login.php` immediately redirects to the provider's authorization endpoint.
2. The plugin generates a random `state` and a PKCE `code_challenge` (S256), stored server-side in WordPress transients. Nothing is written to cookies or the URL.
3. After the user authenticates, the provider redirects to `https://yoursite.com/?jwt_auth_callback=1&code=…&state=…`.
4. The plugin validates the state, exchanges the code for tokens at the provider's token endpoint, and validates the `id_token` JWT against the provider's JWKS.
5. A WordPress user is found (by `sub` meta, then email) or created with the configured default role.
6. A standard WordPress auth cookie is set and the user is redirected to their original destination.

### Authentication flow (proxy mode)

1. The upstream proxy authenticates the user and injects a signed JWT into every request.
2. On each unauthenticated WordPress request, the plugin reads the JWT from the configured cookie, header, or `Authorization: Bearer`.
3. If the JWT is valid and the audience matches, the user is found or created and a WordPress session is established for the current and all future requests.

### User creation

New users are created with:
- `user_login` set to their email address.
- The role defined by `JWT_AUTH_DEFAULT_ROLE` (default: `subscriber`).
- The provider's `sub` claim stored in user meta as `jwt_auth_sub`.

On every subsequent login, the user's first name, last name, display name, and email are synced from the JWT claims. The `sub` meta is used for lookups first, so email changes at the provider are handled gracefully.

### Direct login is blocked

The `authenticate` WordPress filter (priority 1) returns `WP_Error` for all username/password attempts, including programmatic calls and WooCommerce checkout. WP-CLI and cron jobs are exempt.

### WooCommerce

On My Account and Checkout pages, a **"Sign in with SSO"** button is injected:
- Into classic WooCommerce login forms via the `woocommerce_login_form_start` PHP hook.
- Into block-rendered forms via a small `MutationObserver` script (`assets/woo-login.js`).

The button is only shown in OIDC mode. In proxy mode, users are automatically authenticated before the page renders.

---

## Security notes

- **CSRF**: The OIDC `state` parameter is a 128-bit random value stored in a server-side transient. It is single-use and expires after 10 minutes.
- **PKCE**: The `code_verifier` is stored server-side. An intercepted authorization code cannot be exchanged without it.
- **Open redirect**: The post-login `redirect_to` value is stored server-side in the state transient and validated with `wp_validate_redirect()` on use. It is never passed through the browser.
- **JWKS rotation**: Keys are cached for 1 hour. A signature validation failure triggers a one-time cache refresh before failing the request, accommodating live key rotation.
- **Token replay**: WordPress auth cookies provide session continuity. The short-lived ID token (validated once at callback time) is not stored.

---

## Releasing

Releases are fully automated from [Conventional Commits](https://www.conventionalcommits.org/)
via [Release Please](https://github.com/googleapis/release-please). There is no manual version
bump — just write conventional commit messages:

- `fix: ...` → patch release (0.0.x)
- `feat: ...` → minor release (0.x.0)
- `feat!: ...` or a `BREAKING CHANGE:` footer → major release (x.0.0)
- `chore: ...`, `docs: ...`, `refactor: ...` → no release on their own

On every push to `main`, the [Release workflow](.github/workflows/release.yml) opens (or updates)
a **release PR** that accumulates the pending changes and previews the next version + changelog.
Merging that PR:

1. bumps the version in `composer.json` (and the `jwt-auth.php` header) and updates `CHANGELOG.md`;
2. creates the git tag and a GitHub Release with notes generated from the commits;
3. builds the plugin on a Nix runner (`nix build .#zip`) and attaches `jwt-auth.zip`
   (with `vendor/` bundled) as the release asset.

Client sites then pick up the new version automatically via
[plugin-update-checker](https://github.com/YahnisElsts/plugin-update-checker).

The version in the `jwt-auth.php` plugin header is stamped from `composer.json` at build time, so
`composer.json` is the single source of truth. (A from-source/dev checkout may show a stale
header version until built — the published zip is always correct.)

> **Repo setting:** Settings → Actions → General → Workflow permissions must allow
> "Read and write permissions" and "Allow GitHub Actions to create and approve pull requests"
> so Release Please can open the release PR.

## License

This plugin is licensed under the MIT license.
