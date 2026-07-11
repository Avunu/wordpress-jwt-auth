import type { AppConfig } from "../config";
import type { AuthWorkerEnv } from "../env";
import { TokenForm } from "../schemas";
import { getFlowStub } from "../lib/flow";
import { readForm, json } from "../lib/http";
import { verifyPkceS256 } from "../lib/pkce";
import { signIdToken } from "../lib/jwt";
import { randomHex } from "../lib/util";

const ID_TOKEN_TTL = 300;

function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status);
}

/** POST /token — exchange a single-use code (with PKCE proof) for a signed id_token. */
export async function handleToken(request: Request, env: AuthWorkerEnv, config: AppConfig): Promise<Response> {
  const parsed = TokenForm.safeParse(await readForm(request));
  if (!parsed.success) {
    return oauthError("invalid_request", "Malformed token request.");
  }
  const body = parsed.data;

  if (body.client_id !== config.clientId) {
    return oauthError("invalid_client", "Unknown client.", 401);
  }

  // The code is `${flowId}.${secret}` — recover the flow id to address its DO instance.
  const dot = body.code.indexOf(".");
  if (dot <= 0) return oauthError("invalid_grant", "Invalid authorization code.");
  const flowId = body.code.slice(0, dot);

  const result = await getFlowStub(env, flowId).consumeCode(body.code, body.redirect_uri);
  if (!result.ok) {
    return oauthError("invalid_grant", `Authorization code ${result.reason}.`);
  }

  const pkceOk = await verifyPkceS256(body.code_verifier, result.codeChallenge);
  if (!pkceOk) {
    return oauthError("invalid_grant", "PKCE verification failed.");
  }

  const idToken = await signIdToken(config, result.identity, ID_TOKEN_TTL);

  return json({
    access_token: randomHex(32), // opaque; WordPress ignores it but OIDC clients expect a value
    token_type: "Bearer",
    expires_in: ID_TOKEN_TTL,
    id_token: idToken,
    scope: "openid email profile",
  });
}
