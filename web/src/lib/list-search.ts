import type { SearchSchemaInput } from "@tanstack/react-router";

export const PAGE_SIZES = [50, 100, 200] as const;

export type PageSize = (typeof PAGE_SIZES)[number];

export type ListSearch = {
  pageSize: PageSize;
  pageToken: string;
};

export function parseListSearch(search: Partial<ListSearch> & SearchSchemaInput): ListSearch {
  const rawSize = typeof search.pageSize === "number" ? search.pageSize : Number(search.pageSize);
  const pageSize: PageSize = rawSize === 100 || rawSize === 200 ? rawSize : 50;
  const pageToken = typeof search.pageToken === "string" ? search.pageToken : "";
  return { pageSize, pageToken };
}
