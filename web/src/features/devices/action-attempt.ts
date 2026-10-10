import { useSyncExternalStore } from "react";
import type { CreateDeviceActionRequest } from "../../../gen/lindm/admin/v1/device_actions_pb";
import type { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import type { RpcFailure } from "@/lib/errors";

export type DeviceActionAttempt = {
  payload: CreateDeviceActionRequest;
  specSha256: string;
  status: "frozen" | "inflight" | "ambiguous" | "rejected" | "accepted";
  actionId?: string;
  failure: RpcFailure | null;
  approvalId: string;
  approvalAmbiguous: boolean;
  approvalState?: ApprovalState;
};

// Nonsecret, principal-scoped exact retries survive route changes, not a page reload.
// Credentials and revealed recovery keys must never enter this store.
const attempts = new Map<string, DeviceActionAttempt>();
const listeners = new Set<() => void>();
function emit() {
  for (const listener of listeners) listener();
}
subscribeAuthLifetime(() => {
  attempts.clear();
  emit();
});

export function setDeviceActionAttempt(
  lifetime: AuthLifetime,
  deviceId: string,
  attempt: DeviceActionAttempt | null,
): boolean {
  if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return false;
  if (attempt) attempts.set(deviceId, attempt);
  else attempts.delete(deviceId);
  emit();
  return true;
}

export function useDeviceActionAttempt(deviceId: string): DeviceActionAttempt | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => attempts.get(deviceId) ?? null,
  );
}
