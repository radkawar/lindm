import { toJsonString } from "@bufbuild/protobuf";
import { queryOptions } from "@tanstack/react-query";
import {
  TargetExpressionSchema,
  type TargetExpression,
} from "../../../gen/lindm/admin/v1/targeting_pb";
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

// Live membership of an unsaved or saved expression. Nothing is stored; the key
// is the exact expression, so an edit asks again and an unchanged one is reused.
export function dynamicGroupPreviewQueryOptions(
  lifetime: AuthLifetime,
  expression: TargetExpression,
  sampleSize: number,
) {
  return queryOptions({
    queryKey: [
      "targeting",
      lifetime.generation,
      "group-preview",
      toJsonString(TargetExpressionSchema, expression),
      sampleSize,
    ] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.previewDynamicGroup(
        { expression, sampleSize },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
    retry: false,
    staleTime: 30_000,
  });
}

// Custom attribute vocabulary for dynamic-group conditions. One bounded page:
// definitions are an administrator-curated list, not per-device data.
export function attributeDefinitionsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["targeting", lifetime.generation, "attribute-definitions"] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listAttributeDefinitions(
        { pageSize: 200 },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
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
