# Changelog

## [1.0.0](https://github.com/Avunu/wordpress-jwt-auth/compare/jwt-auth-worker-v0.3.0...jwt-auth-worker-v1.0.0) (2026-08-10)


### ⚠ BREAKING CHANGES

* **worker:** the AppConfig type export is replaced by ProviderConfig and WorkerConfig, signIdToken now takes a tenant, and the flow cookie is renamed to __Host-wp_auth_flow, which invalidates logins in flight across a deploy.

### Features

* **worker:** serve many sites from one issuer, with cross-site SSO ([5caacdd](https://github.com/Avunu/wordpress-jwt-auth/commit/5caacdd9434819f460e7a64667031a5a49622b37))

## [0.3.0](https://github.com/Avunu/wordpress-jwt-auth/compare/jwt-auth-worker-v0.2.0...jwt-auth-worker-v0.3.0) (2026-07-14)


### Features

* **worker:** change email auth path ([b62dbb5](https://github.com/Avunu/wordpress-jwt-auth/commit/b62dbb548d0d4b343be8b2905e17be77108b7b15))

## [0.2.0](https://github.com/Avunu/wordpress-jwt-auth/compare/jwt-auth-worker-v0.1.0...jwt-auth-worker-v0.2.0) (2026-07-11)


### Features

* cloudflare worker ([254c7d3](https://github.com/Avunu/wordpress-jwt-auth/commit/254c7d3e403f3b75a9f4fa98e30d2a7a75074d37))
