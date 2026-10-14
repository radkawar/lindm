// SPDX-License-Identifier: Apache-2.0

import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { auditFilter, type AuditSearch } from "./search";

export function auditQueryOptions(lifetime: AuthLifetime, search: AuditSearch) {
  return queryOptions({
    queryKey: ["audit", lifetime.generation, search] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listAuditEvents(
        { pageSize: search.pageSize, pageToken: search.pageToken, filter: auditFilter(search) },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return { events: response.events, nextPageToken: response.nextPageToken };
    },
  });
}

export function auditPickerQueryOptions(
  lifetime: AuthLifetime,
  kind: "actor" | "device",
  request: { namePrefix?: string; afterId?: string; id?: string; pageSize: number },
) {
  return queryOptions({
    queryKey: ["audit-filter-options", lifetime.generation, kind, request] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const options = { signal: AbortSignal.any([signal, lifetime.signal]) };
      if (kind === "actor") {
        const response = await adminClient.listAuditActors(request, options);
        lifetime.signal.throwIfAborted();
        return {
          options: response.actors.map((actor) => ({
            value: actor.id,
            label: actor.displayName.trim() || "Account name unavailable",
          })),
          nextAfterId: response.nextAfterId,
        };
      }
      const response = await adminClient.listAuditDevices(request, options);
      lifetime.signal.throwIfAborted();
      return {
        options: response.devices.map((device) => ({
          value: device.id,
          label: device.hostname.trim() || "Unnamed device",
        })),
        nextAfterId: response.nextAfterId,
      };
    },
  });
}
