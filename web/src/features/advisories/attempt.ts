import { useSyncExternalStore } from "react";
import type { AcceptAdvisoryFindingRequest } from "../../../gen/lindm/admin/v1/advisories_pb";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import type { RpcFailure } from "@/lib/errors";

export type AcceptanceAttempt = {
  payload: AcceptAdvisoryFindingRequest;
  status: "inflight" | "ambiguous" | "rejected" | "succeeded";
  failure: RpcFailure | null;
};
const attempts = new Map<string, AcceptanceAttempt>();
const listeners = new Set<() => void>();
function emit() {
  for (const listener of listeners) listener();
}
subscribeAuthLifetime(() => {
  attempts.clear();
  emit();
});
export function setAcceptanceAttempt(
  lifetime: AuthLifetime,
  key: string,
  attempt: AcceptanceAttempt | null,
) {
  if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return false;
  if (attempt) attempts.set(key, attempt);
  else attempts.delete(key);
  emit();
  return true;
}
export function useAcceptanceAttempt(key: string): AcceptanceAttempt | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => attempts.get(key) ?? null,
  );
}
