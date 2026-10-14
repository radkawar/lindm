// SPDX-License-Identifier: Apache-2.0

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function newRequestId(): string {
  if (typeof crypto.randomUUID !== "function") {
    throw new Error("This browser cannot generate a request UUID.");
  }
  return crypto.randomUUID();
}

export function canonicalUuid(value: string): string | null {
  const trimmed = value.trim();
  if (!UUID_PATTERN.test(trimmed)) return null;
  return trimmed.toLowerCase();
}
