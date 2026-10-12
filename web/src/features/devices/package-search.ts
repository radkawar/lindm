import type { SearchSchemaInput } from "@tanstack/react-router";
import { parseListSearch, type ListSearch } from "@/lib/list-search";

export const deviceTabs = [
  "overview",
  "inventory",
  "resources",
  "encryption",
  "local-admin",
  "actions",
  "assistance",
  "findings",
] as const;
export type DeviceTab = (typeof deviceTabs)[number];

export type PackageSearch = ListSearch & { manager: string; namePrefix: string; tab: DeviceTab };

// Defaults are stripped from the URL so a plain device link stays /devices/<id>.
export const packageSearchDefaults: PackageSearch = {
  pageSize: 50,
  pageToken: "",
  manager: "",
  namePrefix: "",
  tab: "overview",
};

export function parsePackageSearch(
  search: Partial<PackageSearch> & SearchSchemaInput,
): PackageSearch {
  const list = parseListSearch(search);
  const manager = typeof search.manager === "string" ? search.manager : "";
  const namePrefix = typeof search.namePrefix === "string" ? search.namePrefix : "";
  const tab = deviceTabs.find((id) => id === search.tab);
  return {
    ...list,
    manager,
    namePrefix,
    // Package filters and pages only exist on Inventory; older links carry them alone.
    tab: tab ?? (list.pageToken || manager || namePrefix ? "inventory" : "overview"),
  };
}
