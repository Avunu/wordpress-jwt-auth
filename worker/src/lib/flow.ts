import type { LoginFlow } from "../flow-do";
import type { AuthWorkerEnv } from "../env";

/**
 * Resolve the LoginFlow DO instance for a flow id (always addressed by name, so the same id
 * deterministically reaches the same strongly-consistent instance).
 */
export function getFlowStub(env: AuthWorkerEnv, flowId: string): DurableObjectStub<LoginFlow> {
	return env.LOGIN_FLOW.get(env.LOGIN_FLOW.idFromName(flowId));
}
