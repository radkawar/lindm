import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function provisioningTokensQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["provisioning-tokens", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.listProvisioningTokens(
        { pageSize: 50, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}

export function pendingEnrollmentsQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["pending-enrollments", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.getPendingEnrollments(
        { pageSize: 50, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}
