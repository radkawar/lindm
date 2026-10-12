import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function capabilityPoliciesQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["capability-policies", lifetime.generation] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listCapabilityPolicies(
        {},
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
