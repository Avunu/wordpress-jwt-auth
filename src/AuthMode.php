<?php

declare(strict_types=1);

namespace JwtAuth;

enum AuthMode
{
    /** JWT injected by an upstream proxy (Cloudflare Zero Trust, Authentik, Traefik, …). */
    case Proxy;

    /** Full OIDC authorization-code + PKCE redirect flow (Zitadel, Keycloak, Auth0, …). */
    case Oidc;
}
