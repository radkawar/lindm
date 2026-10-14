// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from "react";
import type { ProfileRevision } from "../../../gen/lindm/admin/v1/profiles_pb";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import { newRequestId } from "@/lib/ids";
import type { RpcFailure } from "@/lib/errors";
import type { PublishPayload } from "./model";

export type PublishStatus = "inflight" | "ambiguous" | "conflict" | "rejected" | "published";

export type PublishAttempt = {
  profileId: string;
  mode: "create" | "edit";
  payload: PublishPayload;
  status: PublishStatus;
  failure: RpcFailure | null;
  conflict: boolean;
  refreshedHead: ProfileRevision | null;
  refreshFailure: RpcFailure | null;
  published: ProfileRevision | null;
};

let attempts = new Map<string, PublishAttempt>();
let listSnapshot: PublishAttempt[] = [];
let reservedCreate: { lifetime: AuthLifetime; profileId: string } | null = null;
const listeners = new Set<() => void>();

function emit(): void {
  listSnapshot = [...attempts.values()];
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function sameLifetime(lifetime: AuthLifetime): boolean {
  return getAuthLifetime() === lifetime && !lifetime.signal.aborted;
}

subscribeAuthLifetime(() => {
  attempts = new Map();
  reservedCreate = null;
  emit();
});

export function reservedCreateProfileId(lifetime: AuthLifetime): string {
  if (reservedCreate?.lifetime === lifetime) return reservedCreate.profileId;
  const profileId = newRequestId();
  reservedCreate = { lifetime, profileId };
  return profileId;
}

export function replaceReservedCreateProfileId(lifetime: AuthLifetime): string {
  const profileId = newRequestId();
  reservedCreate = { lifetime, profileId };
  return profileId;
}

export function beginAttempt(lifetime: AuthLifetime, attempt: PublishAttempt): boolean {
  if (!sameLifetime(lifetime)) return false;
  attempts.set(attempt.profileId, attempt);
  emit();
  return true;
}

export function settleAttempt(
  lifetime: AuthLifetime,
  profileId: string,
  patch: Partial<PublishAttempt>,
): void {
  if (!sameLifetime(lifetime)) return;
  const current = attempts.get(profileId);
  if (!current) return;
  attempts.set(profileId, { ...current, ...patch });
  emit();
}

export function clearAttempt(lifetime: AuthLifetime, profileId: string): void {
  if (!sameLifetime(lifetime)) return;
  const current = attempts.get(profileId);
  if (!current) return;
  attempts.delete(profileId);
  if (
    current.status === "published" &&
    reservedCreate?.lifetime === lifetime &&
    reservedCreate.profileId === profileId
  ) {
    reservedCreate = null;
  }
  emit();
}

export function usePublishAttempt(profileId: string): PublishAttempt | null {
  return useSyncExternalStore(subscribe, () => attempts.get(profileId) ?? null);
}

export function usePublishAttempts(): PublishAttempt[] {
  return useSyncExternalStore(subscribe, () => listSnapshot);
}
