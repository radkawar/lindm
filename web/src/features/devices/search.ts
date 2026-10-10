import { create, fromJsonString } from "@bufbuild/protobuf";
import type { SearchSchemaInput } from "@tanstack/react-router";
import { DeviceFilterSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { parseListSearch, type ListSearch } from "@/lib/list-search";

export type DeviceSearch = ListSearch & { filter?: string };

export function parseDeviceSearch(search: Partial<DeviceSearch> & SearchSchemaInput): DeviceSearch {
  return {
    ...parseListSearch(search),
    filter: typeof search.filter === "string" ? search.filter : "",
  };
}

export function deviceFilter(search: DeviceSearch) {
  return search.filter
    ? fromJsonString(DeviceFilterSchema, search.filter)
    : create(DeviceFilterSchema);
}
