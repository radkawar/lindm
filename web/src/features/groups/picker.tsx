import { useState } from "react";
import { keepPreviousData, queryOptions, useQuery } from "@tanstack/react-query";
import { SearchPicker, pickerFooter, type PickerProps } from "@/components/ui/search-picker";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { SEARCH_DELAY_MS, useDelayed } from "@/hooks/use-delayed";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";
import { groupsQueryOptions } from "./view";

// One saved group by ID, wherever it sorts in the paged list; null when it no
// longer exists. Shares the list's key prefix, so saving a group refreshes it.
function groupLookupQueryOptions(lifetime: AuthLifetime, groupId: string) {
  return queryOptions({
    queryKey: ["device-groups", lifetime.generation, "lookup", groupId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.listDeviceGroups(
        { groupIds: [groupId] },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result.groups.find((group) => group.id === groupId) ?? null;
    },
    retry: false,
  });
}

function deviceCount(count: number) {
  return count === 1 ? "1 device" : `${count} devices`;
}

// The server searches every group by any part of its name; paging stays inside
// the open picker.
export function GroupPicker(props: PickerProps) {
  const lifetime = useAuthLifetime();
  const [search, setSearch] = useState("");
  const typed = search.trim().slice(0, 128);
  const nameSearch = useDelayed(typed, SEARCH_DELAY_MS);
  const [page, setPage] = useState({ nameSearch: "", token: "" });
  const pageToken = page.nameSearch === nameSearch ? page.token : "";
  const query = useQuery({
    ...groupsQueryOptions(lifetime, pageToken, nameSearch),
    placeholderData: keepPreviousData,
  });
  const groups = query.error ? [] : (query.data?.groups ?? []);
  // A saved choice on another page or outside the search is still named, not
  // "unavailable".
  const selected = useQuery({
    ...groupLookupQueryOptions(lifetime, props.value),
    enabled: !!props.value && !!query.data && !groups.some((group) => group.id === props.value),
  });
  const options = groups.map((group) => ({
    value: group.id,
    label: group.name,
    description: deviceCount(group.deviceIds.length),
  }));
  if (selected.data && !options.some((option) => option.value === selected.data?.id))
    options.unshift({
      value: selected.data.id,
      label: selected.data.name,
      description: deviceCount(selected.data.deviceIds.length),
    });
  const settled = !query.isFetching && nameSearch === typed;
  const nextPageToken = query.data?.nextPageToken ?? "";
  return (
    <SearchPicker
      {...props}
      search={search}
      onSearchChange={setSearch}
      options={options}
      note="Type any part of a group name. Up to 50 groups at a time."
      footer={pickerFooter({
        loading: query.isPending,
        error: query.error,
        onRetry: () => void query.refetch(),
        empty:
          query.isSuccess && settled && groups.length === 0
            ? nameSearch
              ? `No device group names contain “${nameSearch}”.`
              : "No device groups yet. Create one in Groups."
            : undefined,
        fetching: query.isFetching,
        onFirst: pageToken ? () => setPage({ nameSearch, token: "" }) : undefined,
        onMore: nextPageToken ? () => setPage({ nameSearch, token: nextPageToken }) : undefined,
      })}
    >
      {selected.error ? <RpcError failure={toRpcFailure(selected.error)} /> : null}
    </SearchPicker>
  );
}

// Read-only name for a saved group reference. The first page (shared by every
// name on the screen) answers most; a group past it is looked up by ID.
export function GroupName({ value }: { value: string }) {
  const lifetime = useAuthLifetime();
  const page = useQuery(groupsQueryOptions(lifetime, "", ""));
  const listed = page.data?.groups.find((item) => item.id === value);
  const lookup = useQuery({
    ...groupLookupQueryOptions(lifetime, value),
    enabled: !!value && !!page.data && !listed,
  });
  const group = listed ?? lookup.data;
  if (group) return <>{group.name || "(unnamed group)"}</>;
  if (page.error || lookup.error) return <>(name unavailable)</>;
  if (page.isPending || lookup.isPending) return <>(loading name…)</>;
  return <>(removed group)</>;
}
