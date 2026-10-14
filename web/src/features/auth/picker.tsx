// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { accountsQueryOptions } from "./accounts";

const SHOWN = 100;

// The account list is loaded whole; search runs over every account and shows the first
// matches in username order so no account is hidden behind a page.
export function AccountPicker(props: PickerProps) {
  const query = useQuery(accountsQueryOptions(useAuthLifetime()));
  const [search, setSearch] = useState("");
  const needle = search.trim().toLowerCase();
  const matches = (query.data?.accounts ?? [])
    .filter((account) => account.username.toLowerCase().includes(needle))
    .sort((a, b) => a.username.localeCompare(b.username));
  const shown = matches.slice(0, SHOWN);
  const selected = query.data?.accounts.find((account) => account.id === props.value);
  if (selected && !shown.includes(selected)) shown.unshift(selected);
  return (
    <SearchPicker
      {...props}
      search={search}
      onSearchChange={setSearch}
      options={shown.map((account) => ({
        value: account.id,
        label: account.username,
        description: account.enabled ? account.role : `${account.role} · disabled`,
      }))}
      note={
        matches.length > SHOWN
          ? `Showing ${SHOWN} of ${matches.length} matching accounts. Keep typing to narrow.`
          : undefined
      }
      footer={
        query.isPending || query.error ? (
          <div className="grid gap-2 p-2">
            {query.isPending ? (
              <p role="status" className="text-xs text-muted-foreground">
                Loading accounts…
              </p>
            ) : null}
            {query.error ? (
              <RpcError failure={toRpcFailure(query.error)}>
                <Button
                  type="button"
                  variant="outline"
                  disabled={query.isFetching}
                  onClick={() => void query.refetch()}
                >
                  Retry
                </Button>
              </RpcError>
            ) : null}
          </div>
        ) : undefined
      }
    />
  );
}
