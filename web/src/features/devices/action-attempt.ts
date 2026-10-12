import { useSyncExternalStore } from "react";
import type {
  CreateDeviceActionRequest,
  PreflightDeviceActionResponse,
} from "../../../gen/lindm/admin/v1/device_actions_pb";
import type { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import type { RpcFailure } from "@/lib/errors";

// The server's create-time checks, run for the reviewed request before Send.
export type DeviceActionPreflight =
  | { state: "checking" }
  | { state: "checked"; result: PreflightDeviceActionResponse }
  | { state: "failed"; failure: RpcFailure };

export type DeviceActionAttempt = {
  payload: CreateDeviceActionRequest;
  specSha256: string;
  status: "frozen" | "inflight" | "ambiguous" | "rejected" | "accepted";
  actionId?: string;
  failure: RpcFailure | null;
  approvalId: string;
  approvalAmbiguous: boolean;
  approvalState?: ApprovalState;
  preflight: DeviceActionPreflight;
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

// Applies an async result only while the same reviewed request is still current,
// so a late check never lands on an edited or discarded action. Returns the
// stored attempt, or null when the request changed.
export function updateDeviceActionAttempt(
  lifetime: AuthLifetime,
  deviceId: string,
  payload: CreateDeviceActionRequest,
  update: (current: DeviceActionAttempt) => DeviceActionAttempt,
): DeviceActionAttempt | null {
  const current = attempts.get(deviceId);
  if (!current || current.payload !== payload) return null;
  const next = update(current);
  return setDeviceActionAttempt(lifetime, deviceId, next) ? next : null;
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
