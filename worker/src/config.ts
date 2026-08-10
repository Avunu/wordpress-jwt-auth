import { z } from "zod";
import type { AuthWorkerEnv } from "./env";
import { parseTenants, TenantRegistry } from "./tenant";
import type { Tenant } from "./tenant";

// ---------------------------------------------------------------------------
// Configuration, loaded and validated from Worker vars/secrets.
//
// It splits in two. ProviderConfig is what the issuer itself is — one origin,
// one signing key, one Turnstile widget, one From address — and is shared by
// every site. TenantRegistry is the fleet: who may ask for a token, where they
// may be redirected, and what to call them. If either is missing or malformed
// we throw ConfigError so the request fails with a 500 instead of the worker
// silently minting tokens with a wrong issuer, audience, or key. Error messages
// reference field NAMES only, never values.
// ---------------------------------------------------------------------------

const redirectUriList = z.string().transform((raw, ctx): string[] => {
	const trimmed = raw.trim();
	let list: string[];
	if (trimmed.startsWith("[")) {
		try {
			const parsed: unknown = JSON.parse(trimmed);
			if (!Array.isArray(parsed)) {
				throw new TypeError("not an array");
			}
			list = parsed.map((x) => String(x).trim());
		} catch {
			ctx.addIssue({ code: "custom", message: "must be a JSON array or comma-separated list" });
			return z.NEVER;
		}
	} else {
		list = trimmed.split(",").map((x) => x.trim());
	}
	list = list.filter((x) => x.length > 0);
	if (list.length === 0) {
		ctx.addIssue({ code: "custom", message: "at least one redirect URI is required" });
		return z.NEVER;
	}
	for (const uri of list) {
		if (!URL.canParse(uri)) {
			ctx.addIssue({ code: "custom", message: `invalid redirect URI: ${uri}` });
			return z.NEVER;
		}
	}
	return list;
});

const DAY_MS = 86_400_000;

const EnvProvider = z.object({
	ISSUER: z.url(),
	FROM_EMAIL: z.email(),
	FROM_NAME: z.string().min(1).default("Sign in"),
	TURNSTILE_SITE_KEY: z.string().min(1),
	TURNSTILE_SECRET_KEY: z.string().min(1),
	SIGNING_KEY: z.string().includes("PRIVATE KEY"),
	/** Rolling inactivity window for an SSO session. */
	SESSION_IDLE_DAYS: z.coerce.number().positive().max(365).default(14),
	/** Hard ceiling regardless of activity — a session is never valid past this. */
	SESSION_ABSOLUTE_DAYS: z.coerce.number().positive().max(365).default(90),
});

/** Issuer-wide configuration. Identical for every tenant this worker serves. */
export interface ProviderConfig {
	/** Issuer origin with any trailing slash removed. */
	readonly issuer: string;
	/** Host portion of the issuer. */
	readonly issuerHost: string;
	readonly fromEmail: string;
	readonly fromName: string;
	readonly turnstileSiteKey: string;
	readonly turnstileSecretKey: string;
	/** RS256 private key as normalised PKCS8 PEM (real newlines). */
	readonly signingKeyPem: string;
	readonly sessionIdleMs: number;
	readonly sessionAbsoluteMs: number;
}

export interface WorkerConfig {
	readonly provider: ProviderConfig;
	readonly tenants: TenantRegistry;
}

export class ConfigError extends Error {
	constructor(fields: string[]) {
		super(`Invalid worker configuration: ${fields.join("; ")}`);
		this.name = "ConfigError";
	}
}

/**
 * Some secret stores (e.g. .dev.vars single-line values) encode PEM newlines as the literal
 * two-character sequence backslash-n. Restore real newlines so importPKCS8 can parse the key. A
 * no-op when the PEM already contains real newlines.
 */
function normalisePem(pem: string): string {
	return pem.includes(String.raw`\n`) ? pem.replaceAll(String.raw`\n`, "\n") : pem;
}

/**
 * Isolate-scoped, not request-scoped: the fleet is identical for every request of a deployment, and
 * re-parsing a JSON list of dozens of tenants per request would be pure waste. Keyed on the raw
 * source so a changed var (or a different static array) rebuilds. Mirrors lib/jwt.ts's
 * bundleCache.
 */
let registryCache: { source: unknown; registry: TenantRegistry } | null = null;

/** Build the single-tenant registry that a pre-fleet deployment's vars describe. */
function legacyTenant(env: AuthWorkerEnv, issuerHost: string): { raw: unknown; issues: string[] } {
	const parsed = z
		.object({ CLIENT_ID: z.string().min(1), ALLOWED_REDIRECT_URIS: redirectUriList })
		.safeParse(env);
	if (!parsed.success) {
		return {
			raw: null,
			issues: parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"} ${i.message}`),
		};
	}
	// displayName mirrors what single-tenant deployments have always shown on the sign-in pages.
	const tenant: Tenant = {
		clientId: parsed.data.CLIENT_ID,
		displayName: issuerHost,
		redirectUris: parsed.data.ALLOWED_REDIRECT_URIS,
		sso: true,
	};
	return { raw: [tenant], issues: [] };
}

/**
 * Resolve the fleet from, in order: tenants handed to createAuthWorker(), a TENANTS var, or the
 * legacy CLIENT_ID + ALLOWED_REDIRECT_URIS pair. The last keeps existing single-site deployments
 * working byte-for-byte as they do today.
 */
function loadRegistry(
	env: AuthWorkerEnv,
	staticTenants: readonly unknown[] | undefined,
	issuerHost: string,
): TenantRegistry {
	// A separator that cannot occur in either value, so the two legacy vars can never be re-split
	// into a different pair that yields the same cache key.
	const legacyKey = `${env.CLIENT_ID}\u0000${env.ALLOWED_REDIRECT_URIS}`;
	const source: unknown = staticTenants ?? env.TENANTS ?? legacyKey;
	if (registryCache && registryCache.source === source) {
		return registryCache.registry;
	}

	let raw: unknown;
	let issues: string[] = [];
	if (staticTenants) {
		raw = staticTenants;
	} else if (env.TENANTS) {
		try {
			raw = JSON.parse(env.TENANTS);
		} catch {
			throw new ConfigError(["TENANTS must be valid JSON"]);
		}
	} else {
		({ raw, issues } = legacyTenant(env, issuerHost));
	}

	if (issues.length > 0) {
		throw new ConfigError(issues);
	}

	const parsed = parseTenants(raw);
	if (parsed.issues.length > 0) {
		throw new ConfigError(parsed.issues);
	}

	const registry = new TenantRegistry(parsed.tenants);
	registryCache = { source, registry };
	return registry;
}

export function loadConfig(env: AuthWorkerEnv, staticTenants?: readonly unknown[]): WorkerConfig {
	const parsed = EnvProvider.safeParse(env);
	if (!parsed.success) {
		throw new ConfigError(
			parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"} ${i.message}`),
		);
	}
	const v = parsed.data;
	const issuer = v.ISSUER.replace(/\/+$/, "");
	const issuerHost = new URL(issuer).host;

	return {
		provider: {
			issuer,
			issuerHost,
			fromEmail: v.FROM_EMAIL,
			fromName: v.FROM_NAME,
			turnstileSiteKey: v.TURNSTILE_SITE_KEY,
			turnstileSecretKey: v.TURNSTILE_SECRET_KEY,
			signingKeyPem: normalisePem(v.SIGNING_KEY),
			sessionIdleMs: v.SESSION_IDLE_DAYS * DAY_MS,
			sessionAbsoluteMs: v.SESSION_ABSOLUTE_DAYS * DAY_MS,
		},
		tenants: loadRegistry(env, staticTenants, issuerHost),
	};
}
