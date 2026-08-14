# Playground tests

Real WordPress and real WooCommerce, running on WASM PHP via
[`@wp-playground/cli`](https://www.npmjs.com/package/@wp-playground/cli). No Docker, no database
server, no `wp-env`.

This is a **separate npm package with its own lockfile**. `@wp-playground/cli` and
`playwright-core` are large, and the root `package-lock.json` is consumed by the Nix build — keeping
them apart means the plugin build never has to resolve them.

## Prerequisites

```bash
composer install          # repo root — the plugin fatals without vendor/autoload.php
npm ci && npm run build   # repo root — produces build/woo-login.js
npm --prefix tests/playground ci
```

`run-browser.mjs` drives system Chrome rather than downloading a browser. It defaults to
`/run/current-system/sw/bin/google-chrome-stable`; override with `CHROME_PATH`. Set `WP_VERSION` to
test against something other than `latest`.

## What each test covers

| Test | WordPress? | Browser? | Guards |
| --- | --- | --- | --- |
| `run-assets.mjs` | no | no | The rolldown → PHP seam: `build/woo-login.asset.php` has the shape `enqueueAssets()` `require`s, and the bundle keeps the properties the source promises (no `innerHTML`, login-form selector only). |
| `run-e2e.mjs` | yes | no | The server side: logged-out My Account returns exactly one button, pointing at `wp-login.php`, with the script and its inline config enqueued at the manifest's version. |
| `run-security.mjs` | yes | no | That password login is genuinely dead against real core: the `authenticate` filter ordering, `wp_authenticate()` with a valid password, `wp-login.php`, XML-RPC, and application passwords — plus the passthroughs (cron, empty submission) that must survive. |
| `run-browser.mjs` | yes | yes | The rendered result, after the script has run. |
| `run-exclusive.mjs` | yes | yes | `JWT_AUTH_EXCLUSIVE`: that WooCommerce renders the plugin's templates in place of its own, that the handlers behind them are unhooked from real WooCommerce, that a real HTML parser finds no credential field in `wp_login_form()`'s output, and that `wp-login.php` still does everything that is not a login. |

`run-security.mjs` exists because a hand-rolled fake WordPress structurally cannot catch its bug.
`authenticate` is a **filter**: every callback receives the previous one's return value, and the last
one to run decides. Core registers `wp_authenticate_username_password`,
`wp_authenticate_email_password` and `wp_authenticate_application_password` at priority **20**. The
plugin originally filtered at priority **1**, so core ran afterwards, resolved the password, and
handed back a `WP_User` — silently overwriting the `WP_Error`. Password login worked the entire time.
Only real core, with real callbacks in real order, can show that.

**`run-browser.mjs` is the only test that can see the bug this suite was built for.** The duplicate
"Sign in with SSO" button on `/my-account` was added client-side: PHP emitted one via
`woocommerce_login_form_start`, the fallback script prepended a second, and every server-side
assertion still counted exactly one. It also covers the block checkout, where an earlier selector
list matched `.wc-block-components-form` — the checkout *fields* form — and dropped a button among
the address inputs.

`run-exclusive.mjs` boots its own server from
[`mu-plugins-exclusive/`](mu-plugins-exclusive/), which `require`s the shared config and adds
`JWT_AUTH_EXCLUSIVE`. A second directory rather than a flag because constants are this plugin's
configuration surface and PHP cannot redefine one — exclusive mode has to be a differently-booted
site, not a differently-configured request.

Three of its checks cannot be written any other way:

- **`<template>`.** `wp_login_form()` exposes no hook that can suppress its fields, so the plugin
  closes the form early and wraps them in a `<template>`. Whether that works is a question about the
  HTML5 parser, not about PHP: template contents live in a separate document fragment, so
  `document.querySelector('input[name=pwd]')` must come back `null` while
  `template.content.querySelector(…)` still finds it. The stray `</form>` core appends afterwards is
  likewise something only a parser can pronounce harmless.
- **`remove_action()` addresses.** The plugin unhooks `WC_Form_Handler`'s registration and
  password-reset handlers by naming a hook, a `[class, method]` pair and a priority. Get any of the
  three wrong — because WooCommerce moved it — and WordPress returns `false` and says nothing at all.
  The checks are therefore paired: `process_login` must still be *found* at `wp_loaded`/20 through the
  same convention, so a `false` for the others means removed rather than misaddressed.
- **`get_password_reset_key()` refusing.** WooCommerce's reset flow ends in
  `wc_set_customer_auth_cookie()`, which never touches the `authenticate` filter. That the key is
  refused at source is a claim about core's own function.

To confirm those checks still bite, restore the old behaviour in
[`assets/src/sso-button.ts`](../../assets/src/sso-button.ts) — swap the `.jwt-auth-sso` marker guard
in `injectInto()` for a `data-jwt-auth-done` attribute flag, and widen `LOGIN_FORM_SELECTOR` back to
`.woocommerce-form-login, .wc-block-components-form, .wp-block-woocommerce-customer-account form` —
then `npm run build` and re-run. Four checks fail, `found 2` among them.

## Notes

- **No auto-login.** `Validator::blockDirectAuth()` filters `authenticate` at priority 30 and returns
  `WP_Error` for every username/password attempt, so playground's `login` step cannot succeed with
  this plugin active. Nothing here needs it — a login form only renders for logged-out visitors.
  The priority is load-bearing rather than incidental; `run-security.mjs` explains why and proves it.
- **The cart is seeded before checkout.** An empty cart renders "your cart is currently empty" and
  no fields form, which would let the checkout assertion pass against a page that was never
  rendered.
- **No network stubbing.** Rendering the button calls `Config::detectMode()` and `wp_login_url()`
  and nothing else. `JWT_AUTH_ISSUER` points at an unroutable host so that a test which reaches the
  network fails loudly instead of contacting a real provider — and `run-security.mjs` turns that
  into an assertion, since an unreachable provider is exactly when `wp-login.php` must not fatal.
- WooCommerce is installed from wordpress.org by a blueprint step, so the first run needs network
  access.
