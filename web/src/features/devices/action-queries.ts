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

// Observed storage candidates for one action kind (`escrow_rotate`, `tpm2_bind`,
// `crypto_erase` or `sanitize`). A sanitize `recoveryDigest` (64 hex characters)
// selects the offline-signed recovery image whose readiness is reported.
export function deviceStorageTargetsQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  actionKind: string,
  recoveryDigest = "",
) {
  return queryOptions({
    queryKey: [
      "device-storage-targets",
      lifetime.generation,
      deviceId,
      actionKind,
      recoveryDigest,
    ] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listDeviceStorageTargets(
        {
          deviceId,
          actionKind,
          recoveryImageSha256: recoveryDigest
            ? Uint8Array.from(recoveryDigest.match(/../g)!, (byte) => Number.parseInt(byte, 16))
            : undefined,
        },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
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

export function deviceActionQueryOptions(
  lifetime: AuthLifetime,
  deviceId: string,
  actionId: string,
) {
  return queryOptions({
    queryKey: ["device-action", lifetime.generation, deviceId, actionId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 10_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.getDeviceAction(
        { actionId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (
        !result.action ||
        result.action.actionId !== actionId ||
        result.action.deviceId !== deviceId
      ) {
        throw new Error("The action response does not match this device and action ID.");
      }
      return result.action;
    },
  });
}
