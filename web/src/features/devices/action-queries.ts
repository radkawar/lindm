import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function deviceEncryptionQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  luksUuid = "",
) {
  return queryOptions({
    queryKey: ["device-encryption", lifetime.generation, deviceId, luksUuid] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: async ({ signal }) => {
      const result = await adminClient.getDeviceEncryption(
        { deviceId, luksUuid },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (
        luksUuid &&
        ((result.escrow && result.escrow.luksUuid !== luksUuid) ||
          (result.observation && result.observation.target?.luksUuid !== luksUuid))
      ) {
        throw new Error("Encryption response does not match the selected LUKS volume.");
      }
      return result;
    },
  });
}

export function deviceActionsQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["device-actions", lifetime.generation, deviceId, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 10_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.getDeviceActions(
        { deviceId, pageSize: 25, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
  });
}
