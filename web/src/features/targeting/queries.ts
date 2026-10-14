// SPDX-License-Identifier: Apache-2.0

import { toJsonString } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { queryOptions } from "@tanstack/react-query";
import {
  TargetExpressionSchema,
  type RolloutDeviceState,
  type TargetExpression,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

// A page of dynamic groups in ID order after afterId. A non-empty nameSearch keeps
// only names containing it in any case; restart from "" when it changes.
export function dynamicGroupsQueryOptions(
  lifetime: AuthLifetime,
  afterId: string,
  nameSearch: string,
) {
  return queryOptions({
    queryKey: ["targeting", lifetime.generation, "groups", afterId, nameSearch] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listDynamicGroups(
        { pageSize: 100, afterId: afterId || undefined, nameSearch },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response.groups;
    },
  });
}

// One saved dynamic group by ID, wherever it sorts; null when it no longer exists.
export function dynamicGroupQueryOptions(lifetime: AuthLifetime, groupId: string) {
  return queryOptions({
    queryKey: ["targeting", lifetime.generation, "group", groupId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      try {
        const response = await adminClient.getDynamicGroup(
          { groupId },
          { signal: AbortSignal.any([signal, lifetime.signal]) },
        );
        lifetime.signal.throwIfAborted();
        return response.group ?? null;
      } catch (error) {
        if (ConnectError.from(error).code === Code.NotFound) return null;
        throw error;
      }
    },
    retry: false,
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
      return response;
    },
  });
}

// A page of rollouts in ID order after afterId. A non-empty nameSearch keeps only
// rollouts whose name (ring names joined by ", ") contains it in any case.
export function rolloutsQueryOptions(lifetime: AuthLifetime, afterId: string, nameSearch: string) {
  return queryOptions({
    queryKey: ["targeting", lifetime.generation, "rollouts", afterId, nameSearch] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listRollouts(
        { pageSize: 100, afterId: afterId || undefined, nameSearch },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response.rollouts;
    },
  });
}

export function rolloutDevicesQueryOptions(
  lifetime: AuthLifetime,
  rolloutId: string,
  afterDeviceId: string,
  state: RolloutDeviceState,
) {
  return queryOptions({
    queryKey: [
      "targeting",
      lifetime.generation,
      "rollout-devices",
      rolloutId,
      state,
      afterDeviceId,
    ] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listRolloutDevices(
        { rolloutId, pageSize: 100, afterDeviceId: afterDeviceId || undefined, state },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response.devices;
    },
  });
}
