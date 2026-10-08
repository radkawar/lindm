import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";

export function auditQueryOptions(lifetime: AuthLifetime, pageSize: number, pageToken: string) {
  return queryOptions({
    queryKey: ["audit", lifetime.generation, pageSize, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listAuditEvents(
        { pageSize, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return { events: response.events, nextPageToken: response.nextPageToken };
    },
  });
}
