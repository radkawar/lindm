// SPDX-License-Identifier: Apache-2.0

import type { SearchSchemaInput } from "@tanstack/react-router";
import { parseListSearch, type ListSearch } from "@/lib/list-search";
import { usableUuid } from "./model";

export type ProfileListSearch = {
  pageSize: 50 | 100;
  pageToken: string;
};

export type ProfileDetailSearch = {
  revision: string;
};

export function parseProfileListSearch(
  search: Partial<ListSearch> & SearchSchemaInput,
): ProfileListSearch {
  const parsed = parseListSearch(search);
  return {
    pageSize: parsed.pageSize === 100 ? 100 : 50,
    pageToken: parsed.pageToken,
  };
}

export function parseProfileDetailSearch(
  search: Partial<ProfileDetailSearch> & SearchSchemaInput,
): ProfileDetailSearch {
  if (search.revision === undefined || search.revision === "") return { revision: "" };
  const revision = typeof search.revision === "string" ? usableUuid(search.revision) : null;
  if (revision === null) throw new Error("The version link must contain a valid version ID.");
  return { revision };
}
