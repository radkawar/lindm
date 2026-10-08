import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import type { PackageSearch } from "./package-search";

export function devicesQueryOptions(lifetime: AuthLifetime, pageSize: number, pageToken: string) {
  return queryOptions({
    queryKey: ["devices", lifetime.generation, pageSize, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listDevices(
        { pageSize, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return { devices: response.devices, nextPageToken: response.nextPageToken };
    },
  });
}

export function deviceQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["device", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.getDevice(
        { deviceId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}

export function devicePackagesQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  search: PackageSearch,
) {
  return queryOptions({
    queryKey: ["device-packages", lifetime.generation, deviceId, search] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    // A newly opened view must revalidate before its response is pinned.
    // Pinned pages also recheck authorization and cursor expiry on activation.
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listDevicePackages(
        { deviceId, ...search },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
