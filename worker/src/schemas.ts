import { z } from "zod";

// ---------------------------------------------------------------------------
// Untrusted input at the HTTP boundary — validated, never blindly cast.
// ---------------------------------------------------------------------------

/** OIDC authorization request params the plugin sends to GET /authorize. */
export const AuthorizeParams = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1),
  redirect_uri: z.url(),
  scope: z.string().min(1),
  state: z.string().min(1).max(512),
  code_challenge: z.string().min(20).max(256),
  code_challenge_method: z.literal("S256"),
});
export type AuthorizeParams = z.infer<typeof AuthorizeParams>;

/** Email address, normalised to lowercase + trimmed. */
export const EmailField = z.string().trim().toLowerCase().pipe(z.email().max(254));

/** POST /authorize body — action-tagged union. */
export const RequestCodeForm = z.object({
  action: z.literal("request_code"),
  email: EmailField,
  "cf-turnstile-response": z.string().min(1).max(2048),
});

export const VerifyCodeForm = z.object({
  action: z.literal("verify_code"),
  pin: z.string().regex(/^\d{6}$/),
});

export const AuthorizeForm = z.discriminatedUnion("action", [RequestCodeForm, VerifyCodeForm]);
export type AuthorizeForm = z.infer<typeof AuthorizeForm>;

/** POST /token body from the WordPress plugin's exchangeCode(). */
export const TokenForm = z.object({
  grant_type: z.literal("authorization_code"),
  code: z.string().min(1).max(1024),
  redirect_uri: z.url(),
  code_verifier: z.string().min(43).max(128),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});
export type TokenForm = z.infer<typeof TokenForm>;

// ---------------------------------------------------------------------------
// Durable Object stored state.
// ---------------------------------------------------------------------------

/** The immutable OIDC context captured when the flow is created. */
export const FlowContext = z.object({
  clientId: z.string(),
  redirectUri: z.string(),
  wpState: z.string(),
  scope: z.string(),
  codeChallenge: z.string(),
  createdAt: z.number(),
});
export type FlowContext = z.infer<typeof FlowContext>;

/** Full persisted flow record inside the LoginFlow DO. */
export const FlowRecord = FlowContext.extend({
  email: z.string().nullable(),
  pinHash: z.string().nullable(),
  magicHash: z.string().nullable(),
  pinExpiresAt: z.number(),
  attempts: z.number().int().nonnegative(),
  code: z.string().nullable(),
  codeExpiresAt: z.number(),
  codeUsed: z.boolean(),
});
export type FlowRecord = z.infer<typeof FlowRecord>;

// ---------------------------------------------------------------------------
// Identity claims resolved after a successful challenge.
// ---------------------------------------------------------------------------

export const Identity = z.object({
  email: z.string(),
  sub: z.string(),
  name: z.string().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
});
export type Identity = z.infer<typeof Identity>;

/** Cloudflare Turnstile siteverify response (fields we consume). */
export const TurnstileResult = z.object({
  success: z.boolean(),
  "error-codes": z.array(z.string()).optional(),
});
