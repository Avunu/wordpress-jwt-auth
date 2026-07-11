// Server-rendered HTML for the login pages. All dynamic values are HTML-escaped.
// The Turnstile widget uses the corrected script URL (the PoC pointed at cloudflare.com).

const TURNSTILE_SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js";

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
  h1{font-size:19px;margin:0 0 4px}
  p.sub{margin:0 0 20px;font-size:14px;color:#666}
  label{display:block;font-size:13px;font-weight:600;margin:0 0 6px}
  input[type=email],input[type=text]{width:100%;padding:11px 12px;font-size:16px;border:1px solid #d0d5dd;
    border-radius:8px;margin-bottom:16px}
  input[inputmode=numeric]{letter-spacing:6px;text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  button{width:100%;padding:12px;font-size:15px;font-weight:600;color:#fff;background:#2563eb;border:0;
    border-radius:8px;cursor:pointer}
  button:hover{background:#1d4ed8}
  .cf-turnstile{margin:0 0 16px;display:flex;justify-content:center}
  .msg{font-size:13px;border-radius:8px;padding:10px 12px;margin:0 0 16px}
  .msg.err{background:#fef2f2;color:#b91c1c}
  .msg.ok{background:#f0fdf4;color:#15803d}
  .muted{font-size:12px;color:#98a2b3;margin:16px 0 0;text-align:center}
`;

function page(title: string, inner: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title>
<style>${STYLE}</style>
</head>
<body><div class="card">${inner}</div></body>
</html>`;
}

const RESPONSE_HEADERS = { "Content-Type": "text/html; charset=utf-8" } as const;

function htmlResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: RESPONSE_HEADERS });
}

export function emailFormPage(opts: {
  siteLabel: string;
  siteKey: string;
  error?: string;
  status?: number;
}): Response {
  const err = opts.error ? `<div class="msg err">${esc(opts.error)}</div>` : "";
  return htmlResponse(
    page(
      "Sign in",
      `<h1>Sign in</h1>
       <p class="sub">to ${esc(opts.siteLabel)}</p>
       ${err}
       <form method="POST" autocomplete="on">
         <input type="hidden" name="action" value="request_code">
         <label for="email">Email address</label>
         <input id="email" name="email" type="email" required autofocus placeholder="you@example.com" autocomplete="email">
         <div class="cf-turnstile" data-sitekey="${esc(opts.siteKey)}"></div>
         <button type="submit">Email me a code</button>
       </form>
       <script src="${TURNSTILE_SCRIPT}" async defer></script>`,
    ),
    opts.status ?? 200,
  );
}

export function pinFormPage(opts: {
  siteLabel: string;
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
       <p class="muted">Didn't get it? Check spam, or use the link in the email.</p>`,
    ),
    opts.status ?? 200,
  );
}

/**
 * The magic-link landing page. A bare GET only renders this — it never consumes the token,
 * so an email-security scanner's automatic GET is harmless. The human clicks the button,
 * which POSTs back to /magic to actually sign in.
 */
export function magicConfirmPage(opts: {
  siteLabel: string;
  flow: string;
  token: string;
  email?: string;
}): Response {
  const who = opts.email ? ` as ${esc(opts.email)}` : "";
  return htmlResponse(
    page(
      "Confirm sign-in",
      `<h1>Confirm sign-in</h1>
       <p class="sub">Continue signing in to ${esc(opts.siteLabel)}${who}.</p>
       <form method="POST">
         <input type="hidden" name="flow" value="${esc(opts.flow)}">
         <input type="hidden" name="token" value="${esc(opts.token)}">
         <button type="submit">Sign me in</button>
       </form>
       <p class="muted">Only continue if you started this sign-in.</p>`,
    ),
  );
}

export function errorPage(opts: { title: string; message: string; status?: number }): Response {
  return htmlResponse(
    page(opts.title, `<h1>${esc(opts.title)}</h1><p class="sub">${esc(opts.message)}</p>`),
    opts.status ?? 400,
  );
}
