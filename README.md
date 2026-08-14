# JWT Auth

A WordPress plugin that completely replaces native authentication with an external JWT provider. All login attempts are redirected to the provider; users are created on demand, with the role the site already gives new users. No admin UI — configured entirely via `wp-config.php`.

Password login is refused on every path WordPress exposes. Set [`JWT_AUTH_EXCLUSIVE`](#exclusive-mode) to remove the forms that ask for one too — on a WooCommerce store, that switch also closes the flows WooCommerce uses to hand out a session without consulting the provider at all.

Supports two modes:

| Mode | When to use | Examples |
| --- | --- | --- |
| OIDC | WordPress redirects users to the provider for login | Zitadel, Keycloak, Auth0, Okta |
| Proxy | An upstream proxy injects a signed JWT into every request | Cloudflare Zero Trust, Authentik, Traefik Forward Auth |

* * *

## Requirements

-   PHP 8.4+
-   WordPress 6.4+
-   [Composer](https://getcomposer.org/)

* * *

## Installation

### Recommended: install the release zip

1.  Download `jwt-auth.zip` from the [latest GitHub Release](https://github.com/Avunu/wordpress-jwt-auth/releases/latest)
2.  In WordPress, go to **Plugins → Add New → Upload Plugin** and upload the zip
3.  Configure the required constants in `wp-config.php` (see Configuration section)
4.  Activate the plugin through the WordPress admin interface

The release zip bundles all Composer dependencies, so there is no separate `composer install` step. Once installed, the plugin checks GitHub for new releases and offers one-click updates through the normal WordPress Plugins screen.

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

* * *

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

1.  Create a PKCE application in your Zitadel project.
2.  Set the allowed redirect URI to `https://yoursite.com/?jwt_auth_callback=1`.
3.  Set the post-logout redirect URI to `https://yoursite.com/`.
4.  Copy the issuer URL and client ID into `wp-config.php`.

* * *

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

1.  Add a Cloudflare Access application protecting your WordPress site.
2.  Copy the **Audience Tag** from the application settings into `JWT_AUTH_AUD`.
3.  Set your team domain in `JWT_AUTH_ISSUER` and `JWT_AUTH_JWKS_URI` as shown above.

* * *

### Self-hosted email-PIN provider (Cloudflare Worker)

If you don't want to run a full OIDC server, this repo ships a companion Cloudflare Worker that acts as an OIDC provider and authenticates users by emailing them a 6-digit PIN (plus a one-click magic link). It works with this plugin's **OIDC mode** — no extra constants beyond the three below.

```php
define('JWT_AUTH_ISSUER',        'https://auth.example.com'); // the worker's origin
define('JWT_AUTH_CLIENT_ID',     'yoursite');                  // this site's tenant id in the worker
define('JWT_AUTH_CLIENT_SECRET', ''); // PKCE-only public client (recommended)
```

New visitors who prove ownership of an email address get an account created automatically, as long as the site is [accepting registrations](#turning-account-creation-off).

One worker can serve many sites from a single issuer. Each site is a **tenant** identified by its `JWT_AUTH_CLIENT_ID`, which the worker uses as the token's `aud` claim — so give every site a distinct value, since the audience check below is what keeps one site's tokens from being accepted by another. A multi-tenant worker also offers cross-site single sign-on: verifying a PIN at one site signs the user in at the others (with a confirmation the first time they reach each new one).

The worker's source lives in [`worker/`](worker/) and is published to GitHub Packages as `@avunu/jwt-auth-worker` on each release. Deployments are managed from a private fleet repo that consumes the package. See [`worker/README.md`](worker/README.md) for the tenant shape and the required Cloudflare setup (Email Sending domain onboarding, a Turnstile widget, and a custom domain).

* * *

### All constants

| Constant | Default | Description |
| --- | --- | --- |
| JWT_AUTH_ISSUER | — | Provider base URL. Used for iss claim validation and OIDC discovery. |
| JWT_AUTH_CLIENT_ID | — | OIDC client ID. Presence of this constant activates OIDC mode. |
| JWT_AUTH_CLIENT_SECRET | '' | OIDC client secret. Leave empty for PKCE-only. |
| JWT_AUTH_JWKS_URI | — | JWKS endpoint URL. Required in proxy mode. Overrides OIDC-discovered URI when set in OIDC mode. |
| JWT_AUTH_AUD | — | Expected aud claim value. Required in proxy mode. Overrides client_id audience check in OIDC mode. |
| JWT_AUTH_TOKEN_COOKIE | — | Cookie name carrying the JWT (proxy mode). |
| JWT_AUTH_TOKEN_HEADER | — | HTTP header name carrying the JWT (proxy mode). Falls back to Authorization: Bearer if neither cookie nor header is configured. |
| JWT_AUTH_LOGOUT_URL | — | Provider logout URL. Overrides OIDC end_session_endpoint when set. |
| JWT_AUTH_CLAIM_EMAIL | email | JWT claim containing the user's email address. |
| JWT_AUTH_CLAIM_FIRST_NAME | given_name | JWT claim for first name. |
| JWT_AUTH_CLAIM_LAST_NAME | family_name | JWT claim for last name. |
| JWT_AUTH_CLAIM_NAME | name | JWT claim for display name. |
| JWT_AUTH_REDIRECT | / | Post-login redirect destination. |
| JWT_AUTH_PROVIDER_NAME | SSO | Provider label shown in the WooCommerce sign-in button. |
| JWT_AUTH_EXCLUSIVE | false | Remove the native password forms instead of standing beside them. See [Exclusive mode](#exclusive-mode). |

* * *

## Behaviour

### Authentication flow (OIDC mode)

1.  Any visit to `wp-login.php` immediately redirects to the provider's authorization endpoint.
2.  The plugin generates a random `state` and a PKCE `code_challenge` (S256), stored server-side in WordPress transients. Nothing is written to cookies or the URL.
3.  After the user authenticates, the provider redirects to `https://yoursite.com/?jwt_auth_callback=1&code=…&state=…`.
4.  The plugin validates the state, exchanges the code for tokens at the provider's token endpoint, and validates the `id_token` JWT against the provider's JWKS.
5.  A WordPress user is found (by `sub` meta, then email) or, if the site is [accepting registrations](#turning-account-creation-off), created with the site's [default role for new users](#what-new-accounts-can-do).
6.  A standard WordPress auth cookie is set and the user is redirected to their original destination.

### Authentication flow (proxy mode)

1.  The upstream proxy authenticates the user and injects a signed JWT into every request.
2.  On each unauthenticated WordPress request, the plugin reads the JWT from the configured cookie, header, or `Authorization: Bearer`.
3.  If the JWT is valid and the audience matches, the user is found — or created, if the site is [accepting registrations](#turning-account-creation-off) — and a WordPress session is established for the current and all future requests.

### User creation

New users are created with:

-   `user_login` set to their email address.
-   The role from **Settings → General → "New User Default Role"** (see [below](#what-new-accounts-can-do)).
-   The provider's `sub` claim stored in user meta as `jwt_auth_sub`.

On every subsequent login, the user's first name, last name, display name, and email are synced from the JWT claims. The `sub` meta is used for lookups first, so email changes at the provider are handled gracefully.

### What new accounts can do

The role comes from WordPress's own **Settings → General → "New User Default Role"** (`default_role`), the same setting every other registration path on the site obeys. There is no separate constant.

The plugin does not read the setting at all — `wp_create_user()` applies it, and the plugin deliberately declines to name a role afterwards. That is what makes the guarantee structural rather than vigilant: no provider claim participates in the decision, so no token, however crafted, can ask for a role. The answer is whatever the administrator chose for strangers.

> **Upgrading to 4.0.0:** this replaces the `JWT_AUTH_DEFAULT_ROLE` constant, which is no longer read. If you set it, copy its value into **Settings → General → "New User Default Role"** before updating — otherwise accounts created after the update get whatever that setting already says, which on most installs is `subscriber`. Existing users are unaffected; only newly provisioned accounts take the role. Removing the `define()` from `wp-config.php` is optional, but it is now dead configuration.

### Turning account creation off

Account creation follows WordPress's own **Settings → General → Membership → "Anyone can register"** (`users_can_register`). There is no separate constant. Untick it and the plugin stops minting accounts for people the provider vouches for.

> **Upgrading to 3.0.0:** WordPress ships this box **unticked**, and earlier versions of the plugin ignored it. If your site relies on just-in-time provisioning, tick it before or immediately after updating, or new visitors will be turned away.

What still works with the box unticked:

-   Everyone who already has a WordPress account signs in as usual.
-   A pre-existing account is still adopted on its owner's first federated login — matching an account the site already chose to create is a link, not a signup.

What a turned-away visitor sees:

-   **OIDC mode** — the plugin bounces them through the provider's `end_session_endpoint` and back to `/?jwt_auth_denied=1`, which renders a 403 notice. Ending the provider session matters: otherwise the next attempt silently replays the same rejected identity with no chance to choose a different account. If the provider advertises no end-session endpoint (or `JWT_AUTH_LOGOUT_URL` is set, which the plugin cannot append a return URL to), the notice is shown immediately instead, with a sign-out link when one is configured.
-   **Proxy mode** — they browse the public site anonymously, because the plugin validates a token on _every_ unauthenticated request and an error page there would lock them out of pages they are allowed to read. The 403 notice appears on `wp-admin` and `wp-login.php`, the requests that exist to get somebody signed in. Ajax, cron, and WP-CLI are exempt.

### Direct login is blocked

The `authenticate` WordPress filter returns `WP_Error` for all username/password attempts, including programmatic calls, XML-RPC, application passwords and WooCommerce checkout. WP-CLI and cron jobs are exempt.

The hook runs at **priority 30**, which is the part that makes this true rather than merely intended. `authenticate` is a filter, so the login is decided by whatever the last callback returns, and WordPress core registers its own handlers at priority 20. Registered below them — as this was until v3.0.1 — the refusal was produced and then discarded by core's successful `WP_User`, leaving password login working on every path that does not pass through `wp-login.php`. If you fork this, do not "tidy" that number downwards; `tests/Unit/AuthenticateFilterTest.php` runs the real filter chain and pins both the fix and the original bug.

The forms, however, stay where they were. By default the plugin refuses credentials without removing the boxes that ask for them, so My Account still shows "Username or email address" above the SSO button and the checkout still offers "Returning customer? Click here to login". [Exclusive mode](#exclusive-mode) takes them away.

### Exclusive mode

`define('JWT_AUTH_EXCLUSIVE', true);` makes the provider the only offer on the page rather than one of two.

Most of what it does is presentational, and honestly so: a password box on a site running this plugin is a control that cannot succeed, so removing it changes what a visitor is asked, not what the site accepts. Two of the things it closes are not presentational at all, and they are the reason the switch exists rather than a stylesheet. **WooCommerce grants WordPress sessions on paths that never reach the `authenticate` filter:**

-   `WC_Shortcode_My_Account::reset_password()` calls `wc_set_customer_auth_cookie()` once a new password is set. So "Lost your password?" signed a visitor in on the strength of access to an inbox, with the provider never consulted — a complete bypass of federated login, and one no amount of filtering `authenticate` touches.
-   `WC_Form_Handler::process_registration()` does the same for the Register column, minting a password nobody can use and a session nobody asked the provider about. The checkout "create an account" checkbox and the order-confirmation "Create an account with …" block both end in the same call.

What exclusive mode turns off:

| Surface | What happens instead |
| --- | --- |
| `wp_login_form()` — any theme or plugin call | The fields are moved into an inert `<template>` and the sign-in button is rendered in their place. |
| Core's **Login/out** block with "Display login as form" ticked | Falls back to a plain link to `wp-login.php`, which is where the provider redirect lives. |
| `wp-login.php` sign-in, registration and password-reset screens | A notice. In OIDC mode this is only reached when the provider could not be discovered, so it says so and returns 503; in proxy mode it explains that access is managed upstream. |
| Password reset, everywhere | `allow_password_reset` is false, so no reset key is ever issued — by core, by WooCommerce, or by an administrator's "Send password reset". |
| WooCommerce My Account login **and** registration forms | Replaced by the sign-in button. |
| WooCommerce checkout login prompt, and the `global/form-login.php` form behind the pay and order-received pages | Replaced by the sign-in button, still gated on WooCommerce's own "checkout login reminder" setting. |
| WooCommerce lost-password and reset-password screens | Replaced by an explanation, and the four `WC_Form_Handler` hooks behind them are unhooked. |
| WooCommerce checkout and order-confirmation account creation | Off (`woocommerce_checkout_registration_enabled`, `woocommerce_enable_delayed_account_creation`). New customers get an account on their first federated sign-in instead. |
| `/wc-auth/v1/authorize` — the app-authorisation login | Replaced by the sign-in button, returning to the authorise step afterwards. WooCommerce only special-cases this screen for Jetpack SSO; every other provider got a password box. |

What it deliberately leaves alone:

-   Everything on `wp-login.php` that is not a login: unlocking a password-protected post, confirming a privacy request, the admin-email check, recovery mode, and **logout**. Blocking that screen wholesale is how a lockdown becomes a lockout.
-   `WC_Form_Handler::process_login()`, which ends in `wp_signon()` and is therefore already refused. Leaving it registered means a third-party or AJAX login form that posts there still gets the "sign in with …" notice rather than appearing to do nothing.
-   An administrator setting a user's password in wp-admin. That stays possible and stays useless, which is the correct combination.
-   The password-change fields on WooCommerce's **Edit account** form. WooCommerce provides no hook around that fieldset and copying the template would mean tracking its name, email and billing fields forever; a password set there cannot be used to sign in.

Two consequences worth knowing before you switch it on:

-   Two WooCommerce settings become inert: **Accounts & Privacy → "Allow customers to create an account during checkout"** and **"…on the order confirmation page"**. They will still show as ticked in wp-admin while having no effect.
-   If a site has guest checkout disabled, checkout now requires signing in through the provider — which is the intended reading of "registration required, passwords unavailable", but it is a change in the purchase flow.

Nothing about the switch is a second line of defence for credentials: `authenticate` is still the boundary, and it is on whether or not this is set.

### WooCommerce

A **"Sign in with SSO"** button is added to WooCommerce login forms, in OIDC mode only. In proxy mode users are authenticated before the page renders, so there is nothing to sign in to.

The server does the work. `woocommerce_login_form_start` fires inside the classic login form in both templates WooCommerce renders one from — `myaccount/form-login.php` and `global/form-login.php` (reached from Checkout and the pay/order-received pages) — so My Account and Checkout are both covered, and the button still works with JavaScript switched off.

A small script (`build/woo-login.js`, built from `assets/src/`) covers only what a server-side hook cannot see: a login form added to the page _after_ the response, by an AJAX-rendering theme or a login modal. It skips any form that already contains a button, so on an ordinary page it adds nothing at all.

> Both injectors mark their wrapper `.jwt-auth-sso`, and that shared class is what keeps them from colliding. Before 3.0.1 the script tracked only its own work, and prepended a second button under every server-rendered one on My Account.

Under [exclusive mode](#exclusive-mode) the same two injectors do the same two jobs, one step further: PHP substitutes the templates rather than decorating them, and the script *replaces* a late-rendered form's contents rather than prepending to them. The marker guard is what makes the second safe — every form WooCommerce renders itself has already been swapped server-side and carries the class, so a form still standing when the script runs came from a theme or a modal, which is the one place a password field can survive the switch.

* * *

## Security notes

-   **CSRF**: The OIDC `state` parameter is a 128-bit random value stored in a server-side transient. It is single-use and expires after 10 minutes.
-   **PKCE**: The `code_verifier` is stored server-side. An intercepted authorization code cannot be exchanged without it.
-   **Open redirect**: The post-login `redirect_to` value is stored server-side in the state transient and validated with `wp_validate_redirect()` on use. It is never passed through the browser.
-   **JWKS rotation**: Keys are cached for 1 hour. A signature validation failure triggers a one-time cache refresh before failing the request, accommodating live key rotation.
-   **Token replay**: WordPress auth cookies provide session continuity. The short-lived ID token (validated once at callback time) is not stored.
-   **Sessions granted outside `authenticate`**: filtering `authenticate` covers every path that turns a credential into a `WP_User`, and misses every path that sets an auth cookie without one. On a WooCommerce site there are four, all reached through `wc_set_customer_auth_cookie()`: password reset, My Account registration, checkout account creation, and the order-confirmation create-account block. The first is the sharp one — anybody with access to a customer's inbox could complete WooCommerce's reset flow and be signed in, with the provider never asked. [Exclusive mode](#exclusive-mode) closes all four; without it, they remain open, so on a WooCommerce store treat `JWT_AUTH_EXCLUSIVE` as part of the security configuration rather than a cosmetic preference.

* * *

## Development

```bash
nix develop            # PHP 8.4 with the required extensions, Composer, PHPStan, Node
composer install
composer test          # PHPUnit
composer phpstan       # static analysis, level 8, WordPress-aware
composer check         # both
```

The plugin's suite runs against a small in-memory fake of the WordPress functions it calls ([`tests/Support/functions.php`](tests/Support/functions.php)) rather than a real WordPress install, so it needs no database and finishes in well under a second. `wp_die()` and `wp_redirect()` throw instead of terminating, which is what makes the callback and redirect paths assertable.

The crypto is real: [`KeyFixture`](tests/Support/KeyFixture.php) generates actual RSA keys and signs actual tokens, so the negative tests genuinely demonstrate that a forgery is rejected — `alg: none`, an HS256 token signed with the published public key, a token signed by an unadvertised key, and a tampered payload are each refused.

Both gates run in CI on every push and pull request, offline, via the flake (`nix build .#checks.x86_64-linux.phpunit` and `.phpstan`) — the same commands you can run locally. The worker package has its own suite; see [`worker/README.md`](worker/README.md).

### Browser assets

The WooCommerce fallback script is TypeScript, bundled by [rolldown](https://rolldown.rs/) and checked with [oxlint](https://oxc.rs/) / oxfmt — the same toolchain the worker uses.

```bash
npm ci
npm run check          # oxfmt + oxlint + type-aware lint + tsc
npm run build          # assets/src/*.ts -> build/woo-login.js + build/woo-login.asset.php
npm test               # vitest + jsdom
```

`build/` is generated and gitignored; `nix build .#zip` runs the bundler itself (via `importNpmLock`, so there is no dependency hash to maintain) and ships the output in the plugin zip. The version WordPress caches against is the bundle's own content hash, read from the generated `woo-login.asset.php`.

Four further tests boot **real WordPress and real WooCommerce** on WASM PHP — no Docker, no database:

```bash
npm --prefix tests/playground ci
npm run test:assets     # the build manifest matches what enqueueAssets() requires
npm run test:e2e        # logged-out /my-account returns exactly one button
npm run test:browser    # headless Chrome: exactly one button after the script has run
npm run test:exclusive  # JWT_AUTH_EXCLUSIVE, against real WooCommerce and a real HTML parser
```

`test:browser` earns its keep. The duplicate-button bug lived only in the post-script DOM — PHP emitted one button, the script added another, and every server-side assertion still counted one.

`test:exclusive` earns its keep for the same reason in reverse: three of its claims are about somebody else's code and cannot be made from PHP. That `<template>` renders the login fields inert is a question for an HTML5 parser. That `remove_action()` still names WooCommerce's own hooks correctly is a question for real WooCommerce — a wrong hook, method or priority returns `false` and says nothing, so the suite pairs each removal against a handler that must still be *found* the same way. And that `get_password_reset_key()` refuses is a claim about core.

See [`tests/playground/README.md`](tests/playground/README.md), which also documents how to reintroduce the duplicate-button bug and watch the checks fail.

* * *

## Releasing

Releases are fully automated from [Conventional Commits](https://www.conventionalcommits.org/) via [Release Please](https://github.com/googleapis/release-please). There is no manual version bump — just write conventional commit messages:

-   `fix: ...` → patch release (0.0.x)
-   `feat: ...` → minor release (0.x.0)
-   `feat!: ...` or a `BREAKING CHANGE:` footer → major release (x.0.0)
-   `chore: ...`, `docs: ...`, `refactor: ...` → no release on their own

On every push to `main`, the [Release workflow](.github/workflows/release.yml) opens (or updates) a **release PR** that accumulates the pending changes and previews the next version + changelog. Merging that PR:

1.  bumps the version in `composer.json` (and the `jwt-auth.php` header) and updates `CHANGELOG.md`;
2.  creates the git tag and a GitHub Release with notes generated from the commits;
3.  builds the plugin on a Nix runner (`nix build .#zip`) and attaches `jwt-auth.zip` (with `vendor/` bundled) as the release asset.

Client sites then pick up the new version automatically via [plugin-update-checker](https://github.com/YahnisElsts/plugin-update-checker).

The version in the `jwt-auth.php` plugin header is stamped from `composer.json` at build time, so `composer.json` is the single source of truth. (A from-source/dev checkout may show a stale header version until built — the published zip is always correct.)

> **Repo setting:** Settings → Actions → General → Workflow permissions must allow "Read and write permissions" and "Allow GitHub Actions to create and approve pull requests" so Release Please can open the release PR.

## License

This plugin is licensed under the MIT license.
