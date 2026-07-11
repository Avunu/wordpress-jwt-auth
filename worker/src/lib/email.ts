import type { AppConfig } from "../config";
import type { AuthWorkerEnv } from "../env";

interface LoginEmailArgs {
  to: string;
  pin: string;
  magicUrl: string;
  /** The site the user is signing in to (issuer host), shown for context. */
  siteLabel: string;
  ttlMinutes: number;
}

/** Escape a string for safe interpolation into HTML text/attribute context. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderLoginEmail(args: LoginEmailArgs): {
  subject: string;
  html: string;
  text: string;
} {
  const { pin, magicUrl, siteLabel, ttlMinutes } = args;
  const subject = `Your sign-in code: ${pin}`;

  const text = [
    `Your sign-in code for ${siteLabel} is: ${pin}`,
    ``,
    `Enter this 6-digit code on the sign-in page. It expires in ${ttlMinutes} minutes.`,
    ``,
    `Or sign in instantly with this link (open it on the device you're signing in on):`,
    magicUrl,
    ``,
    `If you didn't try to sign in, you can safely ignore this email.`,
  ].join("\n");

  const html = `<!doctype html>
<html>
  <body style="margin:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a">
    <div style="max-width:480px;margin:0 auto;padding:32px 20px">
      <div style="background:#fff;border-radius:12px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
        <p style="margin:0 0 8px;font-size:14px;color:#666">Sign in to ${esc(siteLabel)}</p>
        <p style="margin:0 0 4px;font-size:14px">Your verification code is:</p>
        <p style="margin:0 0 20px;font-size:40px;font-weight:700;letter-spacing:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace">${esc(pin)}</p>
        <p style="margin:0 0 24px;font-size:13px;color:#666">Enter this code on the sign-in page. It expires in ${ttlMinutes} minutes.</p>
        <a href="${esc(magicUrl)}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-size:15px;font-weight:600">Sign in instantly</a>
        <p style="margin:20px 0 0;font-size:12px;color:#999">If you didn't try to sign in, you can safely ignore this email.</p>
      </div>
    </div>
  </body>
</html>`;

  return { subject, html, text };
}

/**
 * Send the combined PIN + magic-link email via the native Email Sending binding.
 * Throws on send failure (the caller surfaces a retry-able message to the user).
 */
export async function sendLoginEmail(
  env: AuthWorkerEnv,
  config: AppConfig,
  args: LoginEmailArgs,
): Promise<void> {
  const { subject, html, text } = renderLoginEmail(args);
  await env.EMAIL.send({
    to: args.to,
    from: { email: config.fromEmail, name: config.fromName },
    subject,
    html,
    text,
  });
}
