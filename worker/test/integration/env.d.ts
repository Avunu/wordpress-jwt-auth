// The `env` exported by `cloudflare:test` is typed as `Cloudflare.Env`. Populate it with the
// worker's own binding/config contract so `env.LOGIN_FLOW` (and friends) are typed in the
// integration tests without needing a generated worker-configuration.d.ts.
import type { AuthWorkerEnv } from "../../src/env";

declare global {
	namespace Cloudflare {
		interface Env extends AuthWorkerEnv {}
	}
}

export {};
