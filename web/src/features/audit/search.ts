// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import type { SearchSchemaInput } from "@tanstack/react-router";
import { canonicalUuid } from "@/lib/ids";
import { parseListSearch, type ListSearch } from "@/lib/list-search";
import { AuditActionCategory, AuditFilterSchema } from "../../../gen/lindm/audit/v1/filter_pb";

export const AUDIT_VIEWS = [
  {
    value: "human",
    label: "Human actions",
    category: AuditActionCategory.HUMAN_ACTIONS,
  },
  { value: "all", label: "All actions", category: AuditActionCategory.UNSPECIFIED },
  {
    value: "recovery-key-reveals",
    label: "Recovery key reveals",
    category: AuditActionCategory.RECOVERY_KEY_REVEALS,
  },
  {
    value: "destructive-actions",
    label: "Destructive actions",
    category: AuditActionCategory.DESTRUCTIVE_ACTIONS,
  },
  {
    value: "remote-sessions",
    label: "Remote sessions",
    category: AuditActionCategory.REMOTE_SESSIONS,
  },
] as const;

/** Opening the log shows decisions people made, not read-only or system churn. */
export const DEFAULT_AUDIT_VIEW: AuditSearch["view"] = "human";

export type AuditSearch = ListSearch & {
  view: (typeof AUDIT_VIEWS)[number]["value"];
  actorId: string;
  deviceId: string;
  from: string;
  through: string;
};

function identity(value: unknown): string {
  if (value === undefined || value === "") return "";
  const id = typeof value === "string" ? canonicalUuid(value) : null;
  if (!id) throw new Error("The saved audit scope is invalid. Choose an account or device again.");
  return id;
}

function calendarDate(value: unknown): string {
  if (value === undefined || value === "") return "";
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error("Choose a valid audit date range.");
  }
  const date = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value) {
    throw new Error("Choose a valid audit date range.");
  }
  return value;
}

export function parseAuditSearch(search: Partial<AuditSearch> & SearchSchemaInput): AuditSearch {
  const view = search.view ?? DEFAULT_AUDIT_VIEW;
  if (!AUDIT_VIEWS.some((item) => item.value === view))
    throw new Error("Choose a known audit view.");
  const from = calendarDate(search.from);
  const through = calendarDate(search.through);
  if (from && through && from > through)
    throw new Error("The end date must not precede the start date.");
  return {
    ...parseListSearch(search),
    view,
    actorId: identity(search.actorId),
    deviceId: identity(search.deviceId),
    from,
    through,
  };
}

export function lastCalendarWeek(now: Date): Pick<AuditSearch, "from" | "through"> {
  const monday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  monday.setUTCDate(monday.getUTCDate() - ((monday.getUTCDay() + 6) % 7));
  const through = new Date(monday);
  through.setUTCDate(through.getUTCDate() - 1);
  const from = new Date(monday);
  from.setUTCDate(from.getUTCDate() - 7);
  return { from: from.toISOString().slice(0, 10), through: through.toISOString().slice(0, 10) };
}

export function auditFilter(search: AuditSearch) {
  const until = search.through ? new Date(`${search.through}T00:00:00.000Z`) : undefined;
  if (until) until.setUTCDate(until.getUTCDate() + 1);
  return create(AuditFilterSchema, {
    actorId: search.actorId || undefined,
    targetDeviceId: search.deviceId || undefined,
    actionCategory: AUDIT_VIEWS.find((item) => item.value === search.view)!.category,
    occurredFrom: search.from
      ? timestampFromDate(new Date(`${search.from}T00:00:00.000Z`))
      : undefined,
    occurredUntil: until ? timestampFromDate(until) : undefined,
  });
}

export function auditRangeLabel(search: AuditSearch): string {
  if (search.from && search.through) return `${search.from} through ${search.through}, UTC`;
  if (search.from) return `From ${search.from}, UTC`;
  if (search.through) return `Through ${search.through}, UTC`;
  return "All time";
}
