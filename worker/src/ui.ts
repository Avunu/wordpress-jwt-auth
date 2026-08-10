// Server-rendered HTML for the login pages. All dynamic values are HTML-escaped.
// One issuer now fronts many brands, so every page is rendered for a resolved tenant: its name is
// what the person recognises, and its accent/logo are what stop auth.avunu.io looking like a
// phishing interstitial for a site they thought they were signing in to.

import type { Tenant } from "./tenant";

const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
const TURNSTILE_SCRIPT = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js`;
const DEFAULT_ACCENT = "#2563eb";

function esc(s: string): string {
	return s
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

const STYLE = `
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;padding:20px}
  .card{background:#fff;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);padding:32px;width:100%;max-width:380px}
  img.logo{display:block;max-width:180px;max-height:48px;margin:0 auto 20px}
  h1{font-size:19px;margin:0 0 4px}
  p.sub{margin:0 0 20px;font-size:14px;color:#666}
  label{display:block;font-size:13px;font-weight:600;margin:0 0 6px}
  input[type=email],input[type=text]{width:100%;padding:11px 12px;font-size:16px;border:1px solid #d0d5dd;
    border-radius:8px;margin-bottom:16px}
  input[inputmode=numeric]{letter-spacing:6px;text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  button{width:100%;padding:12px;font-size:15px;font-weight:600;color:#fff;background:var(--accent);border:0;
    border-radius:8px;cursor:pointer}
  button:hover{filter:brightness(.92)}
  form.alt{margin:12px 0 0;text-align:center}
  .linkbtn{width:auto;padding:0;background:none;color:var(--accent);font-weight:600;font-size:13px;cursor:pointer}
  .linkbtn:hover{background:none;filter:none;text-decoration:underline}
  .cf-turnstile{margin:0 0 16px;display:flex;justify-content:center}
  .msg{font-size:13px;border-radius:8px;padding:10px 12px;margin:0 0 16px}
  .msg.err{background:#fef2f2;color:#b91c1c}
  .msg.ok{background:#f0fdf4;color:#15803d}
  .muted{font-size:12px;color:#98a2b3;margin:16px 0 0;text-align:center}
`;

/**
 * Turnstile needs its own origin in script-src/frame-src/connect-src, and injects inline styles.
 * Everything else is locked off: no inline script can run, forms can only post back to us, and the
 * pages cannot be framed.
 */
const CSP = [
	"default-src 'none'",
	`script-src ${TURNSTILE_ORIGIN}`,
	`frame-src ${TURNSTILE_ORIGIN}`,
	`connect-src ${TURNSTILE_ORIGIN}`,
	"style-src 'unsafe-inline'",
	"img-src 'self' data: https:",
	"form-action 'self'",
	"base-uri 'none'",
	"frame-ancestors 'none'",
].join("; ");

const RESPONSE_HEADERS = {
	"Content-Type": "text/html; charset=utf-8",
	"Content-Security-Policy": CSP,
	"X-Frame-Options": "DENY",
	// The magic link carries its token in the query string; never hand that to a third party.
	"Referrer-Policy": "no-referrer",
	"Cache-Control": "no-store",
} as const;

function page(title: string, inner: string, tenant: Tenant | null): string {
	const accent = tenant?.accentColor ?? DEFAULT_ACCENT;
	const logo = tenant?.logoUrl
		? `<img class="logo" src="${esc(tenant.logoUrl)}" alt="${esc(tenant.displayName)}">`
		: "";
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title>
<style>:root{--accent:${esc(accent)}}${STYLE}</style>
</head>
<body><div class="card">${logo}${inner}</div></body>
</html>`;
}

function htmlResponse(body: string, status = 200): Response {
	return new Response(body, { status, headers: RESPONSE_HEADERS });
}

export function emailFormPage(opts: {
	tenant: Tenant;
	siteKey: string;
	error?: string;
	status?: number;
}): Response {
	const err = opts.error ? `<div class="msg err">${esc(opts.error)}</div>` : "";
	return htmlResponse(
		page(
			"Sign in",
			`<h1>Sign in</h1>
       <p class="sub">to ${esc(opts.tenant.displayName)}</p>
       ${err}
       <form method="POST" autocomplete="on">
         <input type="hidden" name="action" value="request_code">
         <label for="email">Email address</label>
         <input id="email" name="email" type="email" required autofocus placeholder="you@example.com" autocomplete="email">
         <div class="cf-turnstile" data-sitekey="${esc(opts.siteKey)}"></div>
         <button type="submit">Email me a code</button>
       </form>
       <script src="${TURNSTILE_SCRIPT}" async defer></script>`,
			opts.tenant,
		),
		opts.status ?? 200,
	);
}

export function pinFormPage(opts: {
	tenant: Tenant;
	email: string;
	notice?: string;
	error?: string;
	status?: number;
}): Response {
	const notice = opts.notice ? `<div class="msg ok">${esc(opts.notice)}</div>` : "";
	const err = opts.error ? `<div class="msg err">${esc(opts.error)}</div>` : "";
	return htmlResponse(
		page(
			"Enter your code",
			`<h1>Enter your code</h1>
       <p class="sub">We emailed a 6-digit code to ${esc(opts.email)}</p>
       ${notice}${err}
       <form method="POST" autocomplete="off">
         <input type="hidden" name="action" value="verify_code">
         <label for="pin">6-digit code</label>
         <input id="pin" name="pin" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"
                required autofocus autocomplete="one-time-code" placeholder="000000">
         <button type="submit">Sign in</button>
       </form>
       <form method="POST" class="alt">
         <input type="hidden" name="action" value="change_email">
         <button type="submit" class="linkbtn">Use a different email address</button>
       </form>
       <p class="muted">Didn't get it? Check spam, or use the link in the email.</p>`,
			opts.tenant,
		),
		opts.status ?? 200,
	);
}

/**
 * Shown when an SSO session reaches a site it has never signed into. Arriving at a _known_ site is
 * silent; this one screen is what keeps "signed in at one site" from quietly creating an account on
 * an unrelated brand, and it is the only place to switch identity mid-session.
 */
export function continuePage(opts: { tenant: Tenant; email: string }): Response {
	return htmlResponse(
		page(
			"Continue",
			`<h1>Sign in to ${esc(opts.tenant.displayName)}</h1>
       <p class="sub">You're signed in as ${esc(opts.email)}</p>
       <form method="POST">
         <input type="hidden" name="action" value="continue_sso">
         <button type="submit">Continue</button>
       </form>
       <form method="POST" class="alt">
         <input type="hidden" name="action" value="change_email">
         <button type="submit" class="linkbtn">Use a different email address</button>
       </form>`,
			opts.tenant,
		),
	);
}

/**
 * The magic-link landing page. A bare GET only renders this — it never consumes the token, so an
 * email-security scanner's automatic GET is harmless. The human clicks the button, which POSTs back
 * to /magic to actually sign in.
 */
export function magicConfirmPage(opts: {
	tenant: Tenant | null;
	flow: string;
	token: string;
	email?: string;
}): Response {
	const who = opts.email ? ` as ${esc(opts.email)}` : "";
	const where = opts.tenant ? ` to ${esc(opts.tenant.displayName)}` : "";
	return htmlResponse(
		page(
			"Confirm sign-in",
			`<h1>Confirm sign-in</h1>
       <p class="sub">Continue signing in${where}${who}.</p>
       <form method="POST">
         <input type="hidden" name="flow" value="${esc(opts.flow)}">
         <input type="hidden" name="token" value="${esc(opts.token)}">
         <button type="submit">Sign me in</button>
       </form>
       <p class="muted">Only continue if you started this sign-in.</p>`,
			opts.tenant,
		),
	);
}

/** Tenant is optional here: the request may have failed before we could work out who it was for. */
export function errorPage(opts: {
	title: string;
	message: string;
	status?: number;
	tenant?: Tenant | null;
}): Response {
	return htmlResponse(
		page(
			opts.title,
			`<h1>${esc(opts.title)}</h1><p class="sub">${esc(opts.message)}</p>`,
			opts.tenant ?? null,
		),
		opts.status ?? 400,
	);
}
