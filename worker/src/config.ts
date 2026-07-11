import { z } from "zod";
import type { AuthWorkerEnv } from "./env";

// ---------------------------------------------------------------------------
// Per-deployment configuration, loaded and validated from Worker secrets.
//
// A deployment is "a tenant" purely by virtue of its secret bundle. If any
// Secret is missing or malformed we throw ConfigError so the request fails
// With a 500 instead of the worker silently minting tokens with a wrong issuer,
// Audience, or key. Error messages reference field NAMES only, never values.
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

const EnvSecrets = z.object({
  ISSUER: z.url(),
  CLIENT_ID: z.string().min(1),
  ALLOWED_REDIRECT_URIS: redirectUriList,
  FROM_EMAIL: z.email(),
  FROM_NAME: z.string().min(1).default("Sign in"),
  TURNSTILE_SITE_KEY: z.string().min(1),
  TURNSTILE_SECRET_KEY: z.string().min(1),
  SIGNING_KEY: z.string().includes("PRIVATE KEY"),
});

export interface AppConfig {
  /** Issuer origin with any trailing slash removed. */
  readonly issuer: string;
  /** Host portion of the issuer, used to namespace rate-limit keys per tenant. */
  readonly issuerHost: string;
  readonly clientId: string;
  readonly allowedRedirectUris: readonly string[];
  readonly fromEmail: string;
  readonly fromName: string;
  readonly turnstileSiteKey: string;
  readonly turnstileSecretKey: string;
  /** RS256 private key as normalised PKCS8 PEM (real newlines). */
  readonly signingKeyPem: string;
}

export class ConfigError extends Error {
  constructor(fields: string[]) {
    super(`Invalid worker configuration: ${fields.join("; ")}`);
    this.name = "ConfigError";
  }
}

/**
 * Some secret stores (e.g. .dev.vars single-line values) encode PEM newlines as the
 * literal two-character sequence backslash-n. Restore real newlines so importPKCS8 can
 * parse the key. A no-op when the PEM already contains real newlines.
 */
function normalisePem(pem: string): string {
  return pem.includes(String.raw`\n`) ? pem.replaceAll(String.raw`\n`, "\n") : pem;
}

export function loadConfig(env: AuthWorkerEnv): AppConfig {
  const parsed = EnvSecrets.safeParse(env);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"} ${i.message}`);
    throw new ConfigError(fields);
  }
  const v = parsed.data;
  const issuer = v.ISSUER.replace(/\/+$/, "");
  return {
    issuer,
    issuerHost: new URL(issuer).host,
    clientId: v.CLIENT_ID,
    allowedRedirectUris: v.ALLOWED_REDIRECT_URIS,
    fromEmail: v.FROM_EMAIL,
    fromName: v.FROM_NAME,
    turnstileSiteKey: v.TURNSTILE_SITE_KEY,
    turnstileSecretKey: v.TURNSTILE_SECRET_KEY,
    signingKeyPem: normalisePem(v.SIGNING_KEY),
  };
}
