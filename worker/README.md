# @avunu/jwt-auth-worker

The email-PIN **OIDC identity-provider** Cloudflare Worker for the
[`wordpress-jwt-auth`](../) plugin. It authenticates users by emailing a 6-digit PIN (plus a
one-click magic link) and hands WordPress a signed OIDC `id_token`; WordPress finds/creates a
`subscriber` and logs the user in.

This package is the **reusable core**. It is published to GitHub Packages and consumed by thin
wrappers in the private
[`wordpress-auth-workers`](https://github.com/Avunu/wordpress-auth-workers) fleet repo.
**Deployment lives in the fleet repo, not here.**

## Multi-tenant

One deployment serves many WordPress sites from a single issuer. A **tenant** is identified by its
OIDC `client_id`, which becomes the `aud` claim of the token it receives — and since the plugin
rejects a mismatched audience, that is what keeps one site's tokens useless at another. Each tenant
brings its own redirect-URI allowlist, display name, and optional branding; the issuer, signing key,
Turnstile widget, and From address are shared.

Verifying a PIN also starts an **SSO session**, held in a `UserSession` Durable Object behind a
host-only cookie on the issuer. Returning to a site the browser has used before signs in silently;
arriving at a site it has _not_ used shows a "Continue as you@example.com" confirmation first, so an
unrelated site never gets an account created behind the user's back. `GET /logout` ends that session
fleet-wide, which is also the way to switch accounts.

A deployment with no `SSO_SESSION` binding simply asks for an email and PIN every time, so a
single-site wrapper can adopt this version without a Durable Object migration.

## What it exports

```ts
import { createAuthWorker, LoginFlow, UserSession } from "@avunu/jwt-auth-worker";
import tenants from "./tenants.json";

export { LoginFlow, UserSession }; // Durable Objects — must be re-exported from the entry
export default createAuthWorker({ tenants });
```

The default export is the same handler with no static tenants, reading everything from `env`.

The wrapper's `wrangler.jsonc` supplies the Durable Objects (`LOGIN_FLOW` → `LoginFlow`,
`SSO_SESSION` → `UserSession`, each with a `new_sqlite_classes` migration), the `EMAIL` send
binding, optional rate-limit bindings, and the provider config (`ISSUER`, `FROM_EMAIL`, `FROM_NAME`,
`TURNSTILE_SITE_KEY` as vars; `SIGNING_KEY`, `TURNSTILE_SECRET_KEY` as secrets). Optional:
`SESSION_IDLE_DAYS` (14), `SESSION_ABSOLUTE_DAYS` (90).

### Tenant shape

```jsonc
{
	"clientId": "anabaptistperspectives", // = the site's JWT_AUTH_CLIENT_ID, and its `aud`
	"displayName": "Anabaptist Perspectives", // shown on the sign-in pages and in the email
	"redirectUris": ["https://example.org/?jwt_auth_callback=1"], // exact-match allowlist
	"postLogoutRedirectUris": [], // optional extra post-logout origins
	"replyToEmail": "info@example.org", // optional
	"logoUrl": "https://example.org/logo.svg", // optional
	"accentColor": "#2563eb", // optional
	"sso": true, // optional; false = always demand a fresh PIN
}
```

Tenants may arrive three ways, in order of precedence: passed to `createAuthWorker()` (preferred —
no size limit, reviewable in git), a `TENANTS` JSON var, or the pre-fleet `CLIENT_ID` +
`ALLOWED_REDIRECT_URIS` pair, which is still honoured so existing single-site Workers keep running.
A duplicate `clientId`, or one redirect URI claimed by two tenants, fails the whole config rather
than silently letting one win.

## Design

- Standard OIDC `authorization_code` + PKCE; the signed JWT never appears in a URL.
- One `LoginFlow` Durable Object per attempt: atomic 5-try PIN cap, single-use `flowId.secret`
  authorization code (strongly-consistent `/token` read), alarm cleanup — all inside WordPress's
  fixed 600 s state window. `/token` additionally proves the code was minted for the client
  presenting it.
- One `UserSession` Durable Object per signed-in browser: rolling idle window, hard absolute cap,
  and a record of which tenants the browser has actually used.
- RS256 signing; the public JWKS is derived at runtime from the `SIGNING_KEY` secret.
- Scanner-safe magic link (`GET /magic` renders a confirm page; `POST /magic` consumes).
- Turnstile on the email-send step; native rate-limit bindings keyed on the email address and the
  client IP.
- Cookies use the `__Host-` prefix; the login pages ship a CSP, `no-store`, and `no-referrer`.

## Routes

`GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET|POST /authorize`,
`GET|POST /magic`, `POST /token`, `GET /logout`.

`GET /authorize` accepts `prompt=login` to force a fresh email + PIN despite a live SSO session.

## Develop & test

```bash
npm install
npm run types                 # generate worker-configuration.d.ts (dev only)
cp .dev.vars.example .dev.vars   # fill in a dev SIGNING_KEY (see below) + Turnstile test keys
npm run dev                   # wrangler dev

npm run check                 # format + lint + typecheck
npm test                      # unit (Node) + HTTP/DO integration (workerd)
npm run build                 # emit dist/ (what gets published)
```

The integration suite runs the real router in workerd against a three-tenant fixture fleet and a
signing key generated per run. Most of its assertions are negative: one tenant's `client_id` cannot
be paired with another's `redirect_uri`, a code minted for one tenant cannot be redeemed by another,
and an SSO session never signs in silently at a site it has not been confirmed for.

Generate a dev/prod RS256 key with the fleet repo's `gen-keys` script, or inline:

```bash
node -e "import('jose').then(async j=>{const{privateKey}=await j.generateKeyPair('RS256',{modulusLength:2048,extractable:true});console.log(await j.exportPKCS8(privateKey))})"
```

## Publishing

Automated: `wordpress-jwt-auth`'s Release Please workflow bumps this package's version and runs
`npm publish` to GitHub Packages on each release. Nothing to do manually.
