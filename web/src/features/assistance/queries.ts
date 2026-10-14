// SPDX-License-Identifier: Apache-2.0

import { queryOptions } from "@tanstack/react-query";
import {
  AssistanceReconnectState,
  AssistanceState,
  type AssistanceSession,
} from "../../../gen/lindm/admin/v1/assistance_pb";
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

// Whether a new request can reach a person on the device. It follows check-ins and
// open sessions, so it refreshes with the history.
export function assistanceReadinessQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["assistance-readiness", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 5_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.getAssistanceReadiness(
        { deviceId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (!result.readiness) throw new Error("The server returned no assistance readiness.");
      return result.readiness;
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
    // An ended session in a waiting reconnect workflow keeps polling slowly so
    // the operator sees the next request or the workflow's end.
    refetchInterval: (query) => {
      const session = query.state.data;
      if (session?.state !== AssistanceState.ENDED) return 1_000;
      const workflow = session.reconnect;
      return workflow &&
        workflow.latestSessionId === session.id &&
        (workflow.state === AssistanceReconnectState.WAITING ||
          workflow.state === AssistanceReconnectState.ACTIVE)
        ? 5_000
        : false;
    },
    refetchIntervalInBackground: true,
  });
}

export function assistancePolicyQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["assistance-policy", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: ({ signal }) =>
      adminClient.getAssistancePolicy(
        { deviceId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}

export const ASSISTANCE_RECORDINGS_PAGE_SIZE = 20;

// Archive metadata only: content needs a separately audited retrieval.
export function assistanceRecordingsQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["assistance-recordings", lifetime.generation, deviceId, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 15_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listAssistanceRecordings(
        { deviceId, pageSize: ASSISTANCE_RECORDINGS_PAGE_SIZE, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (result.recordings.some((recording) => recording.deviceId !== deviceId)) {
        throw new Error("The recordings response does not match this device.");
      }
      return result;
    },
  });
}

export function unattendedAssistanceQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["assistance-unattended", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 15_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listUnattendedAssistance(
        { deviceId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (
        result.grants.some((grant) => grant.deviceId !== deviceId) ||
        result.enrollments.some((enrollment) => enrollment.deviceId !== deviceId)
      ) {
        throw new Error("The unattended access response does not match this device.");
      }
      return result;
    },
  });
}

// The caller's own unattended approval requests for this device, read from the
// shared approval inbox. Approval and consumption stay server-authorized.
export function unattendedApprovalsQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["assistance-unattended-approvals", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 15_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listApprovals(
        { pageSize: 200 },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return {
        principalId: result.currentPrincipalId,
        approvals: result.approvals.filter(
          (approval) =>
            approval.action === "assistance.unattended" &&
            approval.deviceId === deviceId &&
            approval.payload.case === "authorizeUnattendedAssistance",
        ),
      };
    },
  });
}
