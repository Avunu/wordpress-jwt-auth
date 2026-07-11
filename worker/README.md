# @avunu/jwt-auth-worker

The email-PIN **OIDC identity-provider** Cloudflare Worker for the
[`wordpress-jwt-auth`](../) plugin. It authenticates users by emailing a 6-digit PIN (plus a
one-click magic link) and hands WordPress a signed OIDC `id_token`; WordPress finds/creates a
`subscriber` and logs the user in.

This package is the **reusable core**. It is published to GitHub Packages and consumed by
thin per-client wrappers in the private
[`wordpress-auth-worker`](https://github.com/Avunu/wordpress-auth-worker) fleet repo — one
deployed Cloudflare Worker per site. **Deployment lives in the fleet repo, not here.**

## What it exports

```ts
import worker, { LoginFlow, type AuthWorkerEnv } from "@avunu/jwt-auth-worker";
// A thin wrapper is just:
export default worker; // the fetch handler
export { LoginFlow }; // the Durable Object (must be re-exported from the entry)
```

The wrapper's `wrangler.jsonc` supplies the `LOGIN_FLOW` Durable Object (with a
`new_sqlite_classes: ["LoginFlow"]` migration), the `EMAIL` send binding, optional rate-limit
bindings, and the config (`ISSUER`, `CLIENT_ID`, `ALLOWED_REDIRECT_URIS`, `FROM_EMAIL`,
`FROM_NAME`, `TURNSTILE_SITE_KEY` as vars; `SIGNING_KEY`, `TURNSTILE_SECRET_KEY` as secrets).

## Design (unchanged from the standalone worker)

- Standard OIDC `authorization_code` + PKCE; the signed JWT never appears in a URL.
- One `LoginFlow` Durable Object per attempt: atomic 5-try PIN cap, single-use `flowId.secret`
  authorization code (strongly-consistent `/token` read), alarm cleanup — all inside
  WordPress's fixed 600 s state window.
- RS256 signing; the public JWKS is derived at runtime from the `SIGNING_KEY` secret.
- Scanner-safe magic link (`GET /magic` renders a confirm page; `POST /magic` consumes).
- Turnstile on the email-send step; native rate-limit bindings, keyed by issuer host.

## Routes

`GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET|POST /authorize`,
`GET|POST /magic`, `POST /token`, `GET /logout`.

## Develop & test

```bash
npm install
npm run types                 # generate worker-configuration.d.ts (dev only)
cp .dev.vars.example .dev.vars   # fill in a dev SIGNING_KEY (see below) + Turnstile test keys
npm run dev                   # wrangler dev

npm run typecheck             # tsc --noEmit
npm test                      # unit (Node) + LoginFlow DO integration (workerd)
npm run build                 # emit dist/ (what gets published)
```

Generate a dev/prod RS256 key with the fleet repo's `gen-keys` script, or inline:

```bash
node -e "import('jose').then(async j=>{const{privateKey}=await j.generateKeyPair('RS256',{modulusLength:2048,extractable:true});console.log(await j.exportPKCS8(privateKey))})"
```

## Publishing

Automated: `wordpress-jwt-auth`'s Release Please workflow bumps this package's version in
lockstep with the plugin and runs `npm publish` to GitHub Packages on each release. Nothing to
do manually.
