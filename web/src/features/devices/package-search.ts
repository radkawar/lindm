import type { SearchSchemaInput } from "@tanstack/react-router";
import { parseListSearch, type ListSearch } from "@/lib/list-search";

export type PackageSearch = ListSearch & { manager: string; namePrefix: string };

export function parsePackageSearch(
  search: Partial<PackageSearch> & SearchSchemaInput,
): PackageSearch {
  return {
    ...parseListSearch(search),
    manager: typeof search.manager === "string" ? search.manager : "",
    namePrefix: typeof search.namePrefix === "string" ? search.namePrefix : "",
  };
}
