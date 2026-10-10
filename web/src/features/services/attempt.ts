import { useSyncExternalStore } from "react";
import type { SetResourceAssignmentRequest } from "../../../gen/lindm/admin/v1/assignments_pb";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import type { RpcFailure } from "@/lib/errors";

export type AssignmentAttempt = {
  payload: SetResourceAssignmentRequest;
  targetLabel: string;
  status: "inflight" | "ambiguous" | "rejected" | "succeeded";
  failure: RpcFailure | null;
};

const attempts = new Map<string, AssignmentAttempt>();
const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

subscribeAuthLifetime(() => {
  attempts.clear();
  emit();
});

export function setAssignmentAttempt(
  lifetime: AuthLifetime,
  deviceId: string,
  attempt: AssignmentAttempt | null,
): boolean {
  if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return false;
  if (attempt) attempts.set(deviceId, attempt);
  else attempts.delete(deviceId);
  emit();
  return true;
}

export function useAssignmentAttempt(deviceId: string): AssignmentAttempt | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => attempts.get(deviceId) ?? null,
  );
}
