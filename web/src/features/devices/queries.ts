import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";

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
