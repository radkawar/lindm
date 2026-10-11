import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { groupsQueryOptions } from "./view";

export function GroupPicker(props: PickerProps) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const query = useQuery(groupsQueryOptions(lifetime, pageToken));
  return (
    <SearchPicker
      {...props}
      options={(query.data?.groups ?? []).map((group) => ({
        value: group.id,
        label: group.name,
        description: `${group.deviceIds.length} devices`,
      }))}
      note="Search within this page of up to 50 groups."
    >
      {query.isPending ? <p role="status">Loading groups…</p> : null}
      {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      <div className="flex gap-2">
        {pageToken ? (
          <Button
            type="button"
            variant="outline"
            disabled={props.disabled || query.isFetching}
            onClick={() => setPageToken("")}
          >
            First groups
          </Button>
        ) : null}
        {query.data?.nextPageToken ? (
          <Button
            type="button"
            variant="outline"
            disabled={props.disabled || query.isFetching}
            onClick={() => setPageToken(query.data?.nextPageToken ?? "")}
          >
            More groups
          </Button>
        ) : null}
      </div>
    </SearchPicker>
  );
}
