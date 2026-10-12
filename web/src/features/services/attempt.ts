import { useSyncExternalStore } from "react";
import type { SetResourceAssignmentRequest } from "../../../gen/lindm/admin/v1/assignments_pb";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import type { RpcFailure } from "@/lib/errors";

// An approval for an attempt the server refused with approval_required. It lives
// with the attempt, outside the Assign profile dialog, so closing the dialog
// (which unmounts its form) never loses an in-flight or ambiguous request.
export type AssignmentApproval = {
  status: "needed" | "inflight" | "ambiguous" | "failed" | "requested";
  approvalId: string;
  failure: RpcFailure | null;
};

export type AssignmentAttempt = {
  payload: SetResourceAssignmentRequest;
  targetLabel: string;
  status: "inflight" | "ambiguous" | "rejected" | "succeeded";
  failure: RpcFailure | null;
  approval: AssignmentApproval | null;
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

// Records approval progress on the device's current attempt, if it still has one.
export function setAssignmentApproval(
  lifetime: AuthLifetime,
  deviceId: string,
  approval: AssignmentApproval,
): boolean {
  const current = attempts.get(deviceId);
  if (!current) return false;
  return setAssignmentAttempt(lifetime, deviceId, { ...current, approval });
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
