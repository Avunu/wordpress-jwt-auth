import { base64url } from "jose";

const enc = new TextEncoder();

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export async function sha256Bytes(input: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return new Uint8Array(digest);
}

export async function sha256Hex(input: string): Promise<string> {
  return toHex(await sha256Bytes(input));
}

/** Unpadded base64url of the SHA-256 digest — the shape PKCE S256 challenges use. */
export async function sha256Base64Url(input: string): Promise<string> {
  return base64url.encode(await sha256Bytes(input));
}

export async function hmacSha256Hex(key: string, message: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return toHex(new Uint8Array(sig));
}

/** Cryptographically-random lowercase hex string of `nBytes` bytes. */
export function randomHex(nBytes: number): string {
  const bytes = new Uint8Array(nBytes);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/**
 * Constant-time equality for two strings. Used to compare secret-derived hashes/tokens.
 * Length is allowed to leak (the compared values are fixed-length hashes/handles), but
 * content comparison takes time independent of where the first differing byte is.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i]! ^ bb[i]!;
  return diff === 0;
}
