// Server-rendered HTML for the login pages. All dynamic values are HTML-escaped.
// One issuer now fronts many brands, so every page is rendered for a resolved tenant: its name is
// what the person recognises, and its accent/logo are what stop auth.avunu.io looking like a
// phishing interstitial for a site they thought they were signing in to.
//
// Every screen is built as a *card* — the markup the client swaps — and a *shell* that wraps one
// card in a document. A plain browser gets shell + card, exactly what it got before; an enhanced
// request gets the card alone. Both come from the same builder, so the two paths cannot drift.

import { CLIENT_SOURCE, CLIENT_SOURCE_HASH, PARTIAL_HEADER, REDIRECT_HEADER } from "./client";
import type { Tenant } from "./tenant";

const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
// Explicit rendering, so a card swapped in after the script has already run still gets a widget.
// This makes the email step JS-dependent, which it already was: RequestCodeForm requires a
// cf-turnstile-response, and Turnstile cannot produce one without JavaScript either way.
const TURNSTILE_SCRIPT = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js?render=explicit&onload=authTurnstileReady`;
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
  button[disabled]{opacity:.6;cursor:default;filter:none}
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
 * `connect-src 'self'` is what lets the client post a form back to us. Everything else is locked
 * off: the only script that may run is the one whose hash is listed here, and the pages cannot be
 * framed.
 *
 * Deliberately no `form-action`. It reads like free defence-in-depth, but Chrome enforces it
 * against the redirect that _results_ from a form submission, which is how it broke sign-in once
 * already. The enhanced path no longer redirects from a form submission at all, but the no-JS path
 * still does, so the directive would still be a loaded gun.
 */
const CSP = [
	"default-src 'none'",
	`script-src '${CLIENT_SOURCE_HASH}' ${TURNSTILE_ORIGIN}`,
	`frame-src ${TURNSTILE_ORIGIN}`,
	`connect-src 'self' ${TURNSTILE_ORIGIN}`,
	"style-src 'unsafe-inline'",
	"img-src 'self' data: https:",
	"base-uri 'none'",
	"frame-ancestors 'none'",
].join("; ");

/**
 * `no-cache` rather than `no-store`: both stop a shared cache serving these pages, but `no-store`
 * additionally evicts the page from the browser's back/forward cache. That matters here because the
 * PIN page is where people leave to go and read their email — and coming back to a page that can no
 * longer be restored is the worst possible moment to lose the flow. The one page that genuinely
 * must never be written to disk is the magic-link confirmation, which carries the token itself.
 */
const CACHE_CONTROL = "private, no-cache, max-age=0, must-revalidate";

const RESPONSE_HEADERS = {
	"Content-Type": "text/html; charset=utf-8",
	"Content-Security-Policy": CSP,
	"X-Frame-Options": "DENY",
	// The magic link carries its token in the query string; never hand that to a third party.
	"Referrer-Policy": "no-referrer",
	"Cache-Control": CACHE_CONTROL,
} as const;

/** One screen: the card the client swaps, plus what a full document around it would need. */
export interface Screen {
	title: string;
	/** The complete `<div class="card" id="card">…</div>`, which is also the swap unit. */
	card: string;
	tenant: Tenant | null;
	status: number;
	cacheControl?: string;
}

function card(inner: string, tenant: Tenant | null): string {
	const logo = tenant?.logoUrl
		? `<img class="logo" src="${esc(tenant.logoUrl)}" alt="${esc(tenant.displayName)}">`
		: "";
	return `<div class="card" id="card">${logo}${inner}</div>`;
}

function document_(screen: Screen): string {
	const accent = screen.tenant?.accentColor ?? DEFAULT_ACCENT;
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(screen.title)}</title>
<style>:root{--accent:${esc(accent)}}${STYLE}</style>
</head>
<body>${screen.card}
<script>${CLIENT_SOURCE}</script>
<script src="${esc(TURNSTILE_SCRIPT)}" async defer></script>
</body>
</html>`;
}

/**
 * Answer a screen: the card alone for an enhanced request, a whole document for a plain browser.
 * The status and every security header are identical either way, so an error keeps its 401 or 410
 * whichever path rendered it.
 */
export function respond(request: Request, screen: Screen): Response {
	const body = request.headers.has(PARTIAL_HEADER) ? screen.card : document_(screen);
	const headers = screen.cacheControl
		? { ...RESPONSE_HEADERS, "Cache-Control": screen.cacheControl }
		: RESPONSE_HEADERS;
	return new Response(body, { status: screen.status, headers });
}

/**
 * A completed sign-in. A plain browser gets today's 302; an enhanced request gets 200 plus the
 * target in a header, because `fetch` follows a 302 transparently and would hand the client the
 * WordPress page's HTML to swap into the card. The header route also means the last hop is a script
 * navigation rather than a form submission, which is what put `form-action` out of the picture.
 */
export function redirectResponse(
	request: Request,
	location: string,
	cookies: readonly string[] = [],
): Response {
	const enhanced = request.headers.has(PARTIAL_HEADER);
	const res = new Response(null, {
		status: enhanced ? 200 : 302,
		headers: enhanced ? { [REDIRECT_HEADER]: location } : { Location: location },
	});
	for (const cookie of cookies) {
		res.headers.append("Set-Cookie", cookie);
	}
	return res;
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

export function emailFormPage(opts: {
	tenant: Tenant;
	siteKey: string;
	error?: string;
	status?: number;
}): Screen {
	const err = opts.error ? `<div class="msg err">${esc(opts.error)}</div>` : "";
	return {
		title: "Sign in",
		tenant: opts.tenant,
		status: opts.status ?? 200,
		card: card(
			`<h1>Sign in</h1>
       <p class="sub">to ${esc(opts.tenant.displayName)}</p>
       ${err}
       <form data-enhance method="post" action="/authorize" autocomplete="on">
         <input type="hidden" name="step" value="request_code">
         <label for="email">Email address</label>
         <input id="email" name="email" type="email" required autofocus placeholder="you@example.com" autocomplete="email">
         <div class="cf-turnstile" data-sitekey="${esc(opts.siteKey)}"></div>
         <button type="submit">Email me a code</button>
       </form>`,
			opts.tenant,
		),
	};
}

export function pinFormPage(opts: {
	tenant: Tenant;
	email: string;
	notice?: string;
	error?: string;
	status?: number;
}): Screen {
	const notice = opts.notice ? `<div class="msg ok">${esc(opts.notice)}</div>` : "";
	const err = opts.error ? `<div class="msg err">${esc(opts.error)}</div>` : "";
	return {
		title: "Enter your code",
		tenant: opts.tenant,
		status: opts.status ?? 200,
		card: card(
			`<h1>Enter your code</h1>
       <p class="sub">We emailed a 6-digit code to ${esc(opts.email)}</p>
       ${notice}${err}
       <form data-enhance method="post" action="/authorize" autocomplete="off">
         <input type="hidden" name="step" value="verify_code">
         <label for="pin">6-digit code</label>
         <input id="pin" name="pin" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"
                required autofocus autocomplete="one-time-code" placeholder="000000">
         <button type="submit">Sign in</button>
       </form>
       <form data-enhance method="post" action="/authorize" class="alt">
         <input type="hidden" name="step" value="change_email">
         <button type="submit" class="linkbtn">Use a different email address</button>
       </form>
       <p class="muted">Didn't get it? Check spam, or use the link in the email.</p>`,
			opts.tenant,
		),
	};
}

/**
 * Shown when an SSO session reaches a site it has never signed into. Arriving at a _known_ site is
 * silent; this one screen is what keeps "signed in at one site" from quietly creating an account on
 * an unrelated brand, and it is the only place to switch identity mid-session.
 */
export function continuePage(opts: { tenant: Tenant; email: string }): Screen {
	return {
		title: "Continue",
		tenant: opts.tenant,
		status: 200,
		card: card(
			`<h1>Sign in to ${esc(opts.tenant.displayName)}</h1>
       <p class="sub">You're signed in as ${esc(opts.email)}</p>
       <form data-enhance method="post" action="/authorize">
         <input type="hidden" name="step" value="continue_sso">
         <button type="submit">Continue</button>
       </form>
       <form data-enhance method="post" action="/authorize" class="alt">
         <input type="hidden" name="step" value="change_email">
         <button type="submit" class="linkbtn">Use a different email address</button>
       </form>`,
			opts.tenant,
		),
	};
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
}): Screen {
	const who = opts.email ? ` as ${esc(opts.email)}` : "";
	const where = opts.tenant ? ` to ${esc(opts.tenant.displayName)}` : "";
	return {
		title: "Confirm sign-in",
		tenant: opts.tenant,
		status: 200,
		// The only page carrying a live credential in its markup, so this one really must not be
		// written to disk — worth the lost back/forward cache that the other pages keep.
		cacheControl: "no-store",
		card: card(
			`<h1>Confirm sign-in</h1>
       <p class="sub">Continue signing in${where}${who}.</p>
       <form data-enhance method="post" action="/magic">
         <input type="hidden" name="flow" value="${esc(opts.flow)}">
         <input type="hidden" name="token" value="${esc(opts.token)}">
         <button type="submit">Sign me in</button>
       </form>
       <p class="muted">Only continue if you started this sign-in.</p>`,
			opts.tenant,
		),
	};
}

/** Tenant is optional here: the request may have failed before we could work out who it was for. */
export function errorPage(opts: {
	title: string;
	message: string;
	status?: number;
	tenant?: Tenant | null;
}): Screen {
	const tenant = opts.tenant ?? null;
	return {
		title: opts.title,
		tenant,
		status: opts.status ?? 400,
		card: card(`<h1>${esc(opts.title)}</h1><p class="sub">${esc(opts.message)}</p>`, tenant),
	};
}
