import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function dynamicGroupsQueryOptions(lifetime: AuthLifetime, afterId: string) {
  return queryOptions({
    queryKey: ["targeting", lifetime.generation, "groups", afterId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listDynamicGroups(
        { pageSize: 100, afterId: afterId || undefined },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response.groups;
    },
  });
}

export function targetAssignmentsQueryOptions(lifetime: AuthLifetime, afterId: string) {
  return queryOptions({
    queryKey: ["targeting", lifetime.generation, "assignments", afterId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listTargetAssignments(
        { pageSize: 100, afterId: afterId || undefined },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response.assignments;
    },
  });
}

export function rolloutsQueryOptions(lifetime: AuthLifetime, afterId: string) {
  return queryOptions({
    queryKey: ["targeting", lifetime.generation, "rollouts", afterId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listRollouts(
        { pageSize: 100, afterId: afterId || undefined },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response.rollouts;
    },
  });
}
