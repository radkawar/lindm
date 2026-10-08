import { useSyncExternalStore } from "react";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";

export type IssuedGrant = {
  requestId: string;
  grantId: string;
  expiresAt: Timestamp | undefined;
  secret: string | null;
  deliveryUnknown: boolean;
  hidden: boolean;
};

let current: IssuedGrant | null = null;
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

export function setIssuedGrant(grant: IssuedGrant | null, lifetime: AuthLifetime): void {
  if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
  current = grant;
  emit();
}

export function clearIssuedGrant(): void {
  if (current === null) return;
  current = null;
  emit();
}

subscribeAuthLifetime(clearIssuedGrant);

export function useIssuedGrant(): IssuedGrant | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}
