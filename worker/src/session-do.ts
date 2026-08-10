import { DurableObject } from "cloudflare:workers";
import type { AuthWorkerEnv } from "./env";

// ---------------------------------------------------------------------------
// The single-sign-on session: one instance per signed-in browser, addressed by
// a random id held in a host-only cookie on the issuer.
//
// This is what makes the fleet feel like one login. Verifying an emailed PIN
// once starts a session here; every later /authorize — from any site — finds it
// and can mint a code without another email. The session records which tenants
// the browser has actually used, so arriving at a *new* site still asks the
// person to confirm rather than silently creating them an account somewhere
// they never chose to sign in to.
// ---------------------------------------------------------------------------

const KEY = "session";

export interface SessionView {
	email: string;
	/** Tenants this browser has already signed into — the ones we may sign in silently. */
	linkedTenants: readonly string[];
}

interface StoredSession {
	email: string;
	createdAt: number;
	lastSeenAt: number;
	/** Hard ceiling: the session dies here no matter how active it has been. */
	absoluteExpiresAt: number;
	/** Rolling inactivity window, captured at start so touch() needs no parameters. */
	idleMs: number;
	linkedTenants: string[];
}

function expiryOf(r: StoredSession): number {
	return Math.min(r.lastSeenAt + r.idleMs, r.absoluteExpiresAt);
}

export class UserSession extends DurableObject<AuthWorkerEnv> {
	private async load(): Promise<StoredSession | null> {
		return (await this.ctx.storage.get<StoredSession>(KEY)) ?? null;
	}

	/** Begin a session for a freshly verified identity, already linked to the site they came from. */
	async start(email: string, clientId: string, idleMs: number, absoluteMs: number): Promise<void> {
		const now = Date.now();
		const record: StoredSession = {
			email,
			createdAt: now,
			lastSeenAt: now,
			absoluteExpiresAt: now + absoluteMs,
			idleMs,
			linkedTenants: [clientId],
		};
		await this.ctx.storage.put(KEY, record);
		await this.ctx.storage.setAlarm(expiryOf(record));
	}

	/** Validate and extend. Null once the session is idle-expired, past its cap, or gone. */
	async touch(): Promise<SessionView | null> {
		return this.ctx.blockConcurrencyWhile(() => this.refresh(null));
	}

	/** Touch(), plus record that this browser has now signed into `clientId`. */
	async link(clientId: string): Promise<SessionView | null> {
		return this.ctx.blockConcurrencyWhile(() => this.refresh(clientId));
	}

	private async refresh(link: string | null): Promise<SessionView | null> {
		const r = await this.load();
		const now = Date.now();
		if (!r || now > r.absoluteExpiresAt || now > r.lastSeenAt + r.idleMs) {
			return null;
		}

		r.lastSeenAt = now;
		if (link !== null && !r.linkedTenants.includes(link)) {
			r.linkedTenants.push(link);
		}
		await this.ctx.storage.put(KEY, r);
		await this.ctx.storage.setAlarm(expiryOf(r));

		return { email: r.email, linkedTenants: r.linkedTenants };
	}

	/** Sign out everywhere: the next /authorize from any site asks for an email + PIN again. */
	async end(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}

	override async alarm(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}
}
