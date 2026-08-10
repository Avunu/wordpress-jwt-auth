import { z } from "zod";

// ---------------------------------------------------------------------------
// Tenants — one WordPress site each, all served by a single issuer.
//
// A tenant is identified by its OIDC `client_id`, which becomes the `aud` claim
// of the id_token it receives. That audience check is what stops a token minted
// for one site from being accepted by another: the plugin rejects a mismatched
// `aud` before it ever looks up a user. Every per-site decision the worker makes
// — which redirect URIs are legal, what name to show, who the email is from —
// is therefore keyed off the resolved tenant, never off global config.
// ---------------------------------------------------------------------------

const HEX_COLOUR = /^#[0-9a-f]{6}$/i;

export const Tenant = z.object({
	/** OIDC client_id. Must match the site's JWT_AUTH_CLIENT_ID, and is used as the `aud` claim. */
	clientId: z.string().min(1),
	/** Human name shown on the sign-in pages and in the email ("Anabaptist Perspectives"). */
	displayName: z.string().min(1),
	/** Exact-match allowlist of OIDC callback URLs. */
	redirectUris: z.array(z.url()).min(1),
	/** Extra origins accepted as post-logout targets, on top of the redirect URIs' own origins. */
	postLogoutRedirectUris: z.array(z.url()).optional(),
	/** Reply-To for sign-in emails; the From address is always the provider's. */
	replyToEmail: z.email().optional(),
	logoUrl: z.url().optional(),
	accentColor: z.string().regex(HEX_COLOUR).optional(),
	/** Participate in cross-site SSO. When false this site always demands a fresh email + PIN. */
	sso: z.boolean().default(true),
});
export type Tenant = z.infer<typeof Tenant>;

/**
 * Validate a raw tenant list. Returns the issues rather than throwing so the caller can fold them
 * into the same ConfigError that a bad provider secret produces — a misconfigured registry must
 * fail the request, not mint tokens for a half-loaded fleet.
 */
export function parseTenants(raw: unknown): { tenants: Tenant[]; issues: string[] } {
	if (!Array.isArray(raw)) {
		return { tenants: [], issues: ["TENANTS must be an array of tenant objects"] };
	}

	const tenants: Tenant[] = [];
	const issues: string[] = [];

	for (const [index, entry] of raw.entries()) {
		const parsed = Tenant.safeParse(entry);
		if (parsed.success) {
			tenants.push(parsed.data);
		} else {
			for (const issue of parsed.error.issues) {
				issues.push(`tenants[${index}].${issue.path.join(".") || "(root)"} ${issue.message}`);
			}
		}
	}

	if (raw.length === 0) {
		issues.push("at least one tenant is required");
	}

	// Two tenants answering to the same client_id or the same callback URL is ambiguous: whichever
	// happened to be listed first would silently win every lookup.
	const seenClientIds = new Set<string>();
	const seenRedirectUris = new Map<string, string>();
	for (const tenant of tenants) {
		if (seenClientIds.has(tenant.clientId)) {
			issues.push(`duplicate clientId: ${tenant.clientId}`);
		}
		seenClientIds.add(tenant.clientId);

		for (const uri of tenant.redirectUris) {
			const owner = seenRedirectUris.get(uri);
			if (owner !== undefined) {
				issues.push(`redirect URI ${uri} is claimed by both ${owner} and ${tenant.clientId}`);
			} else {
				seenRedirectUris.set(uri, tenant.clientId);
			}
		}
	}

	return { tenants, issues };
}

/** Origins a tenant accepts a post-logout redirect to: its callbacks' origins plus any extras. */
function postLogoutOrigins(tenant: Tenant): string[] {
	const sources = [...tenant.redirectUris, ...(tenant.postLogoutRedirectUris ?? [])];
	const origins = new Set<string>();
	for (const uri of sources) {
		try {
			origins.add(new URL(uri).origin);
		} catch {
			// Unreachable: every entry is z.url()-validated. Skip rather than throw at lookup time.
		}
	}
	return [...origins];
}

/** Indexed, immutable view of the fleet. Built once per isolate and shared across requests. */
export class TenantRegistry {
	private readonly byClientId: Map<string, Tenant>;
	/**
	 * Post-logout origin → owning tenant. Distinct tenants may legitimately share an origin (a
	 * subdirectory multisite), in which case the first wins; the match is only used for branding the
	 * signed-out page, so an ambiguous hit is harmless.
	 */
	private readonly byPostLogoutOrigin: Map<string, Tenant>;

	readonly tenants: readonly Tenant[];

	constructor(tenants: readonly Tenant[]) {
		this.tenants = tenants;
		this.byClientId = new Map(tenants.map((t) => [t.clientId, t]));
		this.byPostLogoutOrigin = new Map();
		for (const tenant of tenants) {
			for (const origin of postLogoutOrigins(tenant)) {
				if (!this.byPostLogoutOrigin.has(origin)) {
					this.byPostLogoutOrigin.set(origin, tenant);
				}
			}
		}
	}

	/** The tenant for an OIDC client_id, or null when the client is unknown to this provider. */
	get(clientId: string): Tenant | null {
		return this.byClientId.get(clientId) ?? null;
	}

	/**
	 * The tenant willing to receive a post-logout redirect to `target`, or null when no tenant is.
	 * Matching is by origin because WordPress sends `home_url('/')`, not the callback URL.
	 */
	findPostLogoutTarget(target: string): Tenant | null {
		try {
			return this.byPostLogoutOrigin.get(new URL(target).origin) ?? null;
		} catch {
			return null;
		}
	}
}
