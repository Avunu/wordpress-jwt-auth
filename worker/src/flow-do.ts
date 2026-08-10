import { DurableObject } from "cloudflare:workers";
import type { AuthWorkerEnv } from "./env";
import type { FlowContext, Identity } from "./schemas";
import { randomHex, sha256Hex, timingSafeEqual } from "./lib/util";

const PIN_TTL_MS = 300_000; // 5 min — well inside WordPress's 600s state window
const CODE_TTL_MS = 120_000; // 2 min — code is exchanged within seconds
const FLOW_TTL_MS = 600_000; // 10 min — whole attempt; matches the WP ceiling
const MAX_ATTEMPTS = 5;

/** Persisted flow state (single storage key). Written only by this DO, so trusted. */
interface StoredFlow extends FlowContext {
	email: string | null;
	pinHash: string | null;
	magicHash: string | null;
	pinExpiresAt: number;
	attempts: number;
	code: string | null;
	codeExpiresAt: number;
	codeUsed: boolean;
}

/**
 * A completed flow. `email` is returned only on success — a caller that has just proved control of
 * the inbox may know it (we start their SSO session with it), but a failed guess never learns the
 * address behind the flow.
 */
export interface MintedCode {
	code: string;
	redirectUri: string;
	state: string;
	email: string;
}

export type VerifyResult =
	| ({ ok: true } & MintedCode)
	| { ok: false; reason: "not_found" | "expired" | "locked" | "invalid" };

export type ConsumeResult =
	| { ok: true; identity: Identity; codeChallenge: string; clientId: string }
	| { ok: false; reason: "not_found" | "expired" | "used" | "redirect_mismatch" };

const KEY = "flow";

/** A freshly opened flow: the immutable OIDC context, with no challenge or code yet. */
function blankFlow(context: FlowContext): StoredFlow {
	return {
		...context,
		email: null,
		pinHash: null,
		magicHash: null,
		pinExpiresAt: 0,
		attempts: 0,
		code: null,
		codeExpiresAt: 0,
		codeUsed: false,
	};
}

/**
 * One instance per in-progress login, addressed by a random `flowId`. Being a single authoritative
 * instance gives us (a) atomic PIN-attempt counting — impossible to race with KV — and (b) a
 * strongly-consistent authorization-code read when WordPress calls /token from a different PoP
 * seconds later.
 */
export class LoginFlow extends DurableObject<AuthWorkerEnv> {
	private get flowId(): string {
		const { name } = this.ctx.id;
		if (!name) {
			throw new Error("LoginFlow must be addressed via idFromName");
		}
		return name;
	}

	private async load(): Promise<StoredFlow | null> {
		return (await this.ctx.storage.get<StoredFlow>(KEY)) ?? null;
	}

	/** Initialise the flow with the immutable OIDC context and arm the cleanup alarm. */
	async create(context: FlowContext): Promise<void> {
		await this.ctx.storage.put(KEY, blankFlow(context));
		await this.ctx.storage.setAlarm(context.createdAt + FLOW_TTL_MS);
	}

	/**
	 * Open a flow and mint its code in one shot, for a browser whose SSO session already proves the
	 * identity. Nothing is emailed and no challenge is ever stored — the /token exchange that follows
	 * is byte-identical to the PIN path, so PKCE and single-use semantics are unchanged.
	 */
	async createAndComplete(context: FlowContext, email: string): Promise<MintedCode> {
		return this.ctx.blockConcurrencyWhile(async () => {
			const record = blankFlow(context);
			record.email = email;
			const code = this.mintCode(record, Date.now());
			await this.ctx.storage.put(KEY, record);
			await this.ctx.storage.setAlarm(context.createdAt + FLOW_TTL_MS);
			return { code, redirectUri: record.redirectUri, state: record.wpState, email };
		});
	}

	/** Complete an already-open flow from an SSO session (the "Continue as ..." confirmation). */
	async completeWithIdentity(email: string): Promise<VerifyResult> {
		return this.ctx.blockConcurrencyWhile(async () => {
			const r = await this.load();
			if (!r) {
				return { ok: false, reason: "not_found" };
			}
			const now = Date.now();
			if (now > r.createdAt + FLOW_TTL_MS) {
				return { ok: false, reason: "expired" };
			}
			r.email = email;
			const code = this.mintCode(r, now);
			await this.ctx.storage.put(KEY, r);
			return { ok: true, code, redirectUri: r.redirectUri, state: r.wpState, email };
		});
	}

	/** The immutable OIDC context, or null if the flow is missing/expired. */
	async getContext(): Promise<FlowContext | null> {
		const r = await this.load();
		if (!r || Date.now() > r.createdAt + FLOW_TTL_MS) {
			return null;
		}
		const { email: _e, pinHash: _p, magicHash: _m, ...rest } = r;
		void _e;
		void _p;
		void _m;
		return {
			clientId: rest.clientId,
			redirectUri: rest.redirectUri,
			wpState: rest.wpState,
			scope: rest.scope,
			codeChallenge: rest.codeChallenge,
			createdAt: rest.createdAt,
		};
	}

	/** Store the (already-hashed) PIN + magic-link challenges and reset the attempt counter. */
	async setChallenge(email: string, pinHash: string, magicHash: string): Promise<boolean> {
		return this.ctx.blockConcurrencyWhile(async () => {
			const r = await this.load();
			if (!r || Date.now() > r.createdAt + FLOW_TTL_MS) {
				return false;
			}
			r.email = email;
			r.pinHash = pinHash;
			r.magicHash = magicHash;
			r.pinExpiresAt = Date.now() + PIN_TTL_MS;
			r.attempts = 0;
			await this.ctx.storage.put(KEY, r);
			return true;
		});
	}

	async verifyPin(submittedHash: string): Promise<VerifyResult> {
		return this.ctx.blockConcurrencyWhile(() => this.verifyChallenge("pin", submittedHash));
	}

	async verifyMagic(submittedHash: string): Promise<VerifyResult> {
		return this.ctx.blockConcurrencyWhile(() => this.verifyChallenge("magic", submittedHash));
	}

	/**
	 * Atomic verify: check expiry + attempt cap, constant-time compare the submitted hash, and on
	 * success mint a single-use authorization code. Wrapped in blockConcurrencyWhile so the
	 * read-modify-write can never be raced by a parallel guess.
	 */
	private async verifyChallenge(
		kind: "pin" | "magic",
		submittedHash: string,
	): Promise<VerifyResult> {
		const r = await this.load();
		if (!r) {
			return { ok: false, reason: "not_found" };
		}
		const now = Date.now();
		if (now > r.createdAt + FLOW_TTL_MS || now > r.pinExpiresAt) {
			return { ok: false, reason: "expired" };
		}
		if (r.attempts >= MAX_ATTEMPTS) {
			return { ok: false, reason: "locked" };
		}

		const stored = kind === "pin" ? r.pinHash : r.magicHash;
		const matches = stored !== null && timingSafeEqual(submittedHash, stored);

		if (!matches) {
			r.attempts += 1;
			await this.ctx.storage.put(KEY, r);
			return { ok: false, reason: "invalid" };
		}

		// Unreachable: a challenge only exists because setChallenge stored one alongside an email.
		if (!r.email) {
			return { ok: false, reason: "not_found" };
		}

		const code = this.mintCode(r, now);
		await this.ctx.storage.put(KEY, r);

		return { ok: true, code, redirectUri: r.redirectUri, state: r.wpState, email: r.email };
	}

	/**
	 * Mint the single-use authorization code and retire both challenges so neither can be replayed.
	 * Mutates the record; the caller persists. Shared by every path that completes a flow, so the
	 * code's prefix, TTL, and single-use semantics can't drift between them.
	 */
	private mintCode(r: StoredFlow, now: number): string {
		const code = `${this.flowId}.${randomHex(32)}`;
		r.code = code;
		r.codeExpiresAt = now + CODE_TTL_MS;
		r.codeUsed = false;
		r.pinHash = null;
		r.magicHash = null;
		return code;
	}

	/** Single-use consumption of the authorization code by the /token endpoint. */
	async consumeCode(code: string, redirectUri: string): Promise<ConsumeResult> {
		return this.ctx.blockConcurrencyWhile(async () => {
			const r = await this.load();
			if (!r || !r.code) {
				return { ok: false, reason: "not_found" };
			}
			const now = Date.now();
			if (!timingSafeEqual(code, r.code)) {
				return { ok: false, reason: "not_found" };
			}
			if (r.codeUsed) {
				return { ok: false, reason: "used" };
			}
			if (now > r.codeExpiresAt) {
				return { ok: false, reason: "expired" };
			}
			if (r.redirectUri !== redirectUri) {
				return { ok: false, reason: "redirect_mismatch" };
			}
			if (!r.email) {
				return { ok: false, reason: "not_found" };
			}

			r.codeUsed = true;
			await this.ctx.storage.put(KEY, r);

			const identity: Identity = {
				email: r.email,
				sub: `pin:${await sha256Hex(r.email)}`,
			};
			// clientId travels with the result so /token can prove the caller owns this flow, rather
			// than comparing against a single global client that no longer exists in a fleet.
			return { ok: true, identity, codeChallenge: r.codeChallenge, clientId: r.clientId };
		});
	}

	/** Cleanup alarm — remove all state when the flow's lifetime ends. */
	override async alarm(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}
}
