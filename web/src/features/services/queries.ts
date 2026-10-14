// SPDX-License-Identifier: Apache-2.0

import { queryOptions } from "@tanstack/react-query";
import { ResourceDisposition } from "../../../gen/lindm/admin/v1/assignments_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function resourceStateQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["device-resources", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.getDeviceResourceState(
        { deviceId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
    refetchInterval: (query) =>
      query.state.data?.resources.some(
        (resource) =>
          resource.disposition === ResourceDisposition.PENDING ||
          resource.disposition === ResourceDisposition.IN_PROGRESS,
      )
        ? 5000
        : false,
  });
}
