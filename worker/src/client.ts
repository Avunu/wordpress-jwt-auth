// The entire client. ~50 lines, inlined under a CSP hash so it costs no extra round trip.
//
// It exists to take the browser out of the decision of whether a sign-in proceeds. Every step used
// to be a full navigation, which meant a form POST the browser could refuse, a cross-origin redirect
// it could block, a Set-Cookie it would apply even from a navigation it then abandoned, and a page
// it might not restore from the back/forward cache. Submitting over fetch collapses all of that:
// the response is fully in hand before anything moves, and the final hop becomes a script-initiated
// location assignment, which `form-action` does not govern.
//
// It only ever *adds* behaviour. Every form carries a real `action` and `method`, so if this script
// is blocked, fails to parse, or throws, the browser submits natively and the flow still completes.

/** Header the client sends so the worker knows to answer with a card instead of a whole document. */
export const PARTIAL_HEADER = "X-Partial";

/** Header the worker answers with in place of a 302, since fetch would silently follow that. */
export const REDIRECT_HEADER = "X-Auth-Redirect";

export const CLIENT_SOURCE = `(()=>{
function widgets(){
if(!window.turnstile)return;
for(const el of document.querySelectorAll(".cf-turnstile")){
if(el.dataset.rendered)continue;
el.dataset.rendered="1";
window.turnstile.render(el,{sitekey:el.dataset.sitekey});
}
}
window.authTurnstileReady=widgets;
document.addEventListener("submit",async(event)=>{
const form=event.target.closest("form[data-enhance]");
if(!form)return;
const card=document.querySelector("#card");
if(!card)return;
event.preventDefault();
const submitter=event.submitter;
if(submitter)submitter.disabled=true;
try{
const res=await fetch(form.action,{
method:"POST",
body:new FormData(form,submitter),
headers:{"${PARTIAL_HEADER}":"1"}
});
const to=res.headers.get("${REDIRECT_HEADER}");
if(to){window.location.href=to;return}
card.outerHTML=await res.text();
widgets();
}catch{
if(submitter)submitter.disabled=false;
form.submit();
}
});
})();`;

/**
 * SHA-256 of CLIENT_SOURCE, base64, for script-src. Hardcoded because the CSP header is built
 * synchronously and crypto.subtle is not; test/unit/client.test.ts recomputes it and fails if the
 * two ever drift, which is the only way this can go wrong.
 */
export const CLIENT_SOURCE_HASH = "sha256-MtAq618Edzj+BTIAKQgAHVDF39SdTbSAfjzsoXXJqmc=";
