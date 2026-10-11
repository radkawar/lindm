import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { accountsQueryOptions } from "./accounts";

export function AccountPicker(props: PickerProps) {
  const query = useQuery(accountsQueryOptions(useAuthLifetime()));
  const [page, setPage] = useState(0);
  const accounts = query.data?.accounts ?? [];
  const shown = accounts.slice(page * 100, (page + 1) * 100);
  const selected = accounts.find((account) => account.id === props.value);
  if (selected && !shown.includes(selected)) shown.unshift(selected);
  return (
    <SearchPicker
      {...props}
      options={shown.map((account) => ({
        value: account.id,
        label: account.username,
        description: account.role,
      }))}
      note="Search within this page of up to 100 accounts."
    >
      {query.isPending ? <p role="status">Loading accounts…</p> : null}
      {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      <div className="flex gap-2">
        {page > 0 ? (
          <Button
            type="button"
            variant="outline"
            disabled={props.disabled}
            onClick={() => setPage(page - 1)}
          >
            Previous accounts
          </Button>
        ) : null}
        {(page + 1) * 100 < accounts.length ? (
          <Button
            type="button"
            variant="outline"
            disabled={props.disabled}
            onClick={() => setPage(page + 1)}
          >
            More accounts
          </Button>
        ) : null}
      </div>
    </SearchPicker>
  );
}
