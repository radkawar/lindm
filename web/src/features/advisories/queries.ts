import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function deviceFindingsQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["advisory-findings", lifetime.generation, deviceId, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    staleTime: 0,
    refetchInterval: 30_000,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listDeviceFindings(
        { deviceId, pageToken, pageSize: 50 },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}

export function advisorySummaryQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["advisory-summary", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    staleTime: 0,
    refetchInterval: 30_000,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listAdvisorySummary(
        { pageToken, pageSize: 50 },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}

export function advisoryFeedsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["advisory-feeds", lifetime.generation] as const,
    meta: { authGeneration: lifetime.generation },
    staleTime: 0,
    refetchInterval: 30_000,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listAdvisoryFeeds(
        {},
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
