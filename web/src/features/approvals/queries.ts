import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function approvalsQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["approvals", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.listApprovals(
        { pageSize: 50, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}

// The first page of one device's requests in the caller's inbox; open requests
// sort first, so an open revocation is always on it.
export function deviceApprovalsQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["approvals", lifetime.generation, "device", deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.listApprovals(
        { pageSize: 50, deviceId },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}
