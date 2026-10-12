import type { SearchSchemaInput } from "@tanstack/react-router";
import { parseListSearch, type ListSearch } from "@/lib/list-search";
import type { DeviceActionKind } from "./action-display";
import { simpleActionKinds } from "./action-menu";

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

// `action` names the simple device action whose dialog is open.
export type PackageSearch = ListSearch & {
  manager: string;
  namePrefix: string;
  tab: DeviceTab;
  action?: DeviceActionKind;
};

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
  const action = simpleActionKinds.find((kind) => kind === search.action);
  return {
    ...list,
    manager,
    namePrefix,
    tab: tab ?? "overview",
    ...(action ? { action } : {}),
  };
}
