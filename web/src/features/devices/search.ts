// SPDX-License-Identifier: Apache-2.0

import { create, fromJsonString } from "@bufbuild/protobuf";
import type { SearchSchemaInput } from "@tanstack/react-router";
import {
  DeviceFilterSchema,
  DeviceSortField,
  DeviceSortSchema,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { parseListSearch, type ListSearch } from "@/lib/list-search";

// Server-side orders the device list offers; the server sorts across all pages.
export const deviceSortFields = {
  hostname: DeviceSortField.HOSTNAME,
  contact: DeviceSortField.LAST_SEEN,
  os: DeviceSortField.OPERATING_SYSTEM,
} as const;
export type DeviceSortColumn = keyof typeof deviceSortFields;

export type DeviceSearch = ListSearch & {
  filter?: string;
  // Case-insensitive part of a hostname.
  hostnameSearch?: string;
  sort?: DeviceSortColumn;
  order?: "asc" | "desc";
  advisoryId?: string;
  advisorySeverity?: string;
};

export function parseDeviceSearch(search: Partial<DeviceSearch> & SearchSchemaInput): DeviceSearch {
  const sort =
    typeof search.sort === "string" && Object.hasOwn(deviceSortFields, search.sort)
      ? search.sort
      : undefined;
  return {
    ...parseListSearch(search),
    filter: typeof search.filter === "string" ? search.filter : "",
    hostnameSearch: typeof search.hostnameSearch === "string" ? search.hostnameSearch : "",
    advisoryId: typeof search.advisoryId === "string" ? search.advisoryId : "",
    advisorySeverity: typeof search.advisorySeverity === "string" ? search.advisorySeverity : "",
    ...(sort ? { sort, order: search.order === "desc" ? "desc" : "asc" } : {}),
  };
}

export function deviceFilter(search: DeviceSearch) {
  return search.filter
    ? fromJsonString(DeviceFilterSchema, search.filter)
    : create(DeviceFilterSchema);
}

export function deviceSort(search: DeviceSearch) {
  return create(DeviceSortSchema, {
    field: search.sort ? deviceSortFields[search.sort] : DeviceSortField.UNSPECIFIED,
    descending: search.order === "desc",
  });
}
