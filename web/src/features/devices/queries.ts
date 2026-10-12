import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import type { PackageSearch } from "./package-search";
import { deviceFilter, deviceSort, type DeviceSearch } from "./search";

export function devicesQueryOptions(lifetime: AuthLifetime, search: DeviceSearch) {
  return queryOptions({
    queryKey: ["devices", lifetime.generation, search] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listDevices(
        {
          pageSize: search.pageSize,
          pageToken: search.pageToken,
          filter: deviceFilter(search),
          sort: deviceSort(search),
          hostnameSearch: search.hostnameSearch ?? "",
        },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
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

// Status and escrow metadata only. Revealed passwords never enter a query.
export function localAdminPasswordQueryOptions(lifetime: AuthLifetime, deviceId: string) {
  return queryOptions({
    queryKey: ["local-admin-password", lifetime.generation, deviceId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.getLocalAdminPasswordStatus(
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

export function attributeDefinitionsQueryOptions(lifetime: AuthLifetime, afterKey: string) {
  return queryOptions({
    queryKey: ["attribute-definitions", lifetime.generation, afterKey] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listAttributeDefinitions(
        { pageSize: 100, afterKey },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
