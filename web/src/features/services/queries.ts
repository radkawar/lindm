import { queryOptions } from "@tanstack/react-query";
import { ServiceResourceDisposition } from "../../../gen/lindm/admin/v1/service_assignments_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function serviceStateQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["device-services", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.getDeviceServiceState(
        { deviceId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
    refetchInterval: (query) =>
      query.state.data?.resources.some(
        (resource) =>
          resource.disposition === ServiceResourceDisposition.PENDING ||
          resource.disposition === ServiceResourceDisposition.IN_PROGRESS,
      )
        ? 5000
        : false,
  });
}

export function serviceProfileHeadsQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["service-profile-heads", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listServiceProfiles(
        { pageSize: 100, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
