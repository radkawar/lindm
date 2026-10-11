import { queryOptions } from "@tanstack/react-query";
import { AssistanceState, type AssistanceSession } from "../../../gen/lindm/admin/v1/assistance_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export const ASSISTANCE_HISTORY_PAGE_SIZE = 20;

export function assistanceSessionsQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["assistance-sessions", lifetime.generation, deviceId, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 5_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listAssistanceSessions(
        { deviceId, pageSize: ASSISTANCE_HISTORY_PAGE_SIZE, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (result.sessions.some((session) => session.deviceId !== deviceId)) {
        throw new Error("The assistance history response does not match this device.");
      }
      return result;
    },
  });
}

// The viewer follows one session at 1 s while it is open; polling stops once it ended.
export function assistanceSessionQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  sessionId: string,
) {
  return queryOptions({
    queryKey: ["assistance-session", lifetime.generation, deviceId, sessionId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: async ({ signal }): Promise<AssistanceSession> => {
      const result = await adminClient.getAssistanceSession(
        { sessionId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      const session = result.session;
      if (!session || session.id !== sessionId || session.deviceId !== deviceId) {
        throw new Error("The assistance response does not match this device and session ID.");
      }
      return session;
    },
    refetchInterval: (query) => (query.state.data?.state === AssistanceState.ENDED ? false : 1_000),
    refetchIntervalInBackground: true,
  });
}
