import { hmacSha256Hex, randomHex, timingSafeEqual } from "./util";

/**
 * A uniform 6-digit numeric PIN from the CSPRNG. Rejection sampling removes the small modulo bias
 * so every code from 000000–999999 is equally likely.
 */
export function generatePin(): string {
	const range = 1_000_000;
	const limit = Math.floor(0xff_ff_ff_ff / range) * range;
	const buf = new Uint32Array(1);
	let x: number;
	do {
		crypto.getRandomValues(buf);
		x = buf[0] ?? 0;
	} while (x >= limit);
	return (x % range).toString().padStart(6, "0");
}

/** 256-bit magic-link secret (hex). */
export function generateMagicToken(): string {
	return randomHex(32);
}

/**
 * Keyed hash of a challenge secret, using the (random, per-flow) flow id as the HMAC key. Only the
 * hash is persisted, so a leak of DO storage never exposes the live PIN/token.
 */
export function hashSecret(secret: string, flowId: string): Promise<string> {
	return hmacSha256Hex(flowId, secret);
}

export async function verifySecret(
	secret: string,
	flowId: string,
	storedHash: string,
): Promise<boolean> {
	return timingSafeEqual(await hashSecret(secret, flowId), storedHash);
}
