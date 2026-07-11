/// <reference types="@cloudflare/workers-types" />
import type { LoginFlow } from "./flow-do";

/**
 * Bindings + configuration every deployment provides. Config values may arrive as committed
 * `vars` or as per-Worker secrets — the worker reads them identically through `env`, so this
 * interface makes no distinction. Consumers (thin wrappers) supply these via their
 * `wrangler.jsonc` bindings/vars plus `wrangler secret` for the sensitive ones.
 */
export interface AuthWorkerEnv {
  // --- Bindings ---
  /** Native Email Sending binding. */
  EMAIL: SendEmail;
  /** One LoginFlow Durable Object instance per in-progress login. */
  LOGIN_FLOW: DurableObjectNamespace<LoginFlow>;
  /** Optional per-email send throttle. */
  RL_EMAIL?: RateLimit;
  /** Optional per-IP throttle. */
  RL_IP?: RateLimit;

  // --- Config (committed vars or secrets) ---
  ISSUER: string;
  CLIENT_ID: string;
  ALLOWED_REDIRECT_URIS: string;
  FROM_EMAIL: string;
  FROM_NAME?: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
  SIGNING_KEY: string;
}
