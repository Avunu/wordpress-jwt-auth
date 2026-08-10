// The fixture fleet, shared by vitest.integration.config.ts (which feeds it to the worker as the
// TENANTS var) and by the tests themselves. Three tenants: two ordinary ones so every cross-tenant
// check has a genuine "other site" to point at, and one with SSO switched off.

export const ISSUER = "https://auth.test";

export const ALPHA_REDIRECT = "https://alpha.test/?jwt_auth_callback=1";
export const BETA_REDIRECT = "https://beta.test/?jwt_auth_callback=1";
export const SOLO_REDIRECT = "https://solo.test/?jwt_auth_callback=1";

export const TENANTS = [
	{
		clientId: "alpha",
		displayName: "Alpha Site",
		redirectUris: [ALPHA_REDIRECT, "https://recovery.alpha.test/?jwt_auth_callback=1"],
	},
	{ clientId: "beta", displayName: "Beta Site", redirectUris: [BETA_REDIRECT] },
	{ clientId: "solo", displayName: "Solo Site", redirectUris: [SOLO_REDIRECT], sso: false },
];

/** PKCE S256 pair from RFC 7636 Appendix B. */
export const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
