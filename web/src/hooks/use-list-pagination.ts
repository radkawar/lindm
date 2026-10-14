// SPDX-License-Identifier: Apache-2.0

import { useRef } from "react";
import type { PageSize } from "@/lib/list-search";

type ListPage = { pageSize: PageSize; pageToken: string };

export function useListPagination(page: ListPage, onSearch: (next: ListPage) => void) {
  const previous = useRef(new Map<string, string>());
  const key = page.pageToken;
  return {
    previousLabel: previous.current.has(key) ? "Previous page" : "First page",
    previous: () =>
      onSearch({ pageSize: page.pageSize, pageToken: previous.current.get(key) ?? "" }),
    next: (pageToken: string) => {
      previous.current.set(pageToken, page.pageToken);
      onSearch({ pageSize: page.pageSize, pageToken });
    },
  };
}
