// SPDX-License-Identifier: Apache-2.0

import { createContext, useContext, type ReactNode } from "react";
import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import type { TargetRef } from "../../../gen/lindm/policy/v1/targeting_pb";
import {
  SearchPicker,
  pickerFooter,
  type PickerOption,
  type PickerSlot,
  type PickerProps,
} from "@/components/ui/search-picker";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { SEARCH_DELAY_MS, useDelayed } from "@/hooks/use-delayed";
import { toRpcFailure } from "@/lib/errors";
import { dynamicGroupQueryOptions, dynamicGroupsQueryOptions } from "./queries";

// A display name resolved from an identity; `ready` is false while loading or
// when the name could not be found, and `text` then says why.
export type NameLabel = { text: string; ready: boolean };
export type ProfileVersionLabel = NameLabel & { short: string };
// A name rendered for an identity, composed by the route (groups pages).
export type NameSlot = (props: { value: string }) => ReactNode;

export type TargetPickers = {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
  profileRevisionPicker: PickerSlot;
};
// Read-only names for saved records, composed by the route like the pickers.
export type TargetNames = {
  useTargetLabel: (target?: TargetRef) => NameLabel;
  useProfileVersionLabel: (id: string) => ProfileVersionLabel;
};

const Context = createContext<{ pickers: TargetPickers; names?: TargetNames } | null>(null);
export function TargetPickerProvider({
  pickers,
  names,
  children,
}: {
  pickers: TargetPickers;
  names?: TargetNames;
  children: ReactNode;
}) {
  return <Context value={{ pickers, names }}>{children}</Context>;
}
export function useTargetPickers() {
  const value = useContext(Context);
  if (!value) throw new Error("Targeting pickers must be composed by the route.");
  return value.pickers;
}
export function useTargetNames() {
  const names = useContext(Context)?.names;
  if (!names) throw new Error("Targeting names must be composed by the route.");
  return names;
}

export function useDynamicGroupLabel(id: string): NameLabel {
  const query = useQuery({ ...dynamicGroupQueryOptions(useAuthLifetime(), id), enabled: !!id });
  const group = query.data;
  if (group) return { text: group.name || "Unnamed dynamic group", ready: true };
  if (query.isPending) return { text: "Loading name…", ready: false };
  if (query.error) return { text: "Name unavailable", ready: false };
  return { text: "Dynamic group not found", ready: false };
}

export function useTargetLabel(target?: TargetRef): NameLabel {
  return useTargetNames().useTargetLabel(target);
}

export function TargetName({ target }: { target?: TargetRef }) {
  return <>{useTargetLabel(target).text}</>;
}

export function ProfileVersionName({ value }: { value: string }) {
  return <>{useTargetNames().useProfileVersionLabel(value).text}</>;
}

const PAGE_SIZE = 100;

// Search text as the server takes it, once typing pauses, with the ID-ordered
// position that restarts whenever the search changes.
function useServerSearch() {
  const [search, setSearch] = useState("");
  const typed = search.trim().slice(0, 128);
  const nameSearch = useDelayed(typed, SEARCH_DELAY_MS);
  const [page, setPage] = useState({ nameSearch: "", after: "" });
  return {
    search,
    setSearch,
    typed,
    nameSearch,
    after: page.nameSearch === nameSearch ? page.after : "",
    goTo: (after: string) => setPage({ nameSearch, after }),
  };
}

// The server searches every dynamic group by any part of its name.
export function DynamicGroupPicker(props: PickerProps) {
  const lifetime = useAuthLifetime();
  const search = useServerSearch();
  const query = useQuery({
    ...dynamicGroupsQueryOptions(lifetime, search.after, search.nameSearch),
    placeholderData: keepPreviousData,
  });
  const groups = query.error ? [] : (query.data ?? []);
  // A saved choice on another page or outside the search is still named.
  const selected = useQuery({
    ...dynamicGroupQueryOptions(lifetime, props.value),
    enabled: !!props.value && !!query.data && !groups.some((g) => g.groupId === props.value),
  });
  const options: PickerOption[] = groups.map((group) => ({
    value: group.groupId,
    label: group.name,
  }));
  if (selected.data && !options.some((option) => option.value === selected.data?.groupId))
    options.unshift({ value: selected.data.groupId, label: selected.data.name });
  const settled = !query.isFetching && search.nameSearch === search.typed;
  const last = groups.length === PAGE_SIZE ? (groups.at(-1)?.groupId ?? "") : "";
  return (
    <SearchPicker
      {...props}
      search={search.search}
      onSearchChange={search.setSearch}
      options={options}
      note="Type any part of a dynamic group name. Up to 100 groups at a time."
      footer={pickerFooter({
        loading: query.isPending,
        error: query.error,
        onRetry: () => void query.refetch(),
        empty:
          query.isSuccess && settled && groups.length === 0
            ? search.nameSearch
              ? `No dynamic group names contain “${search.nameSearch}”.`
              : "No dynamic groups yet. Choose a device group instead, or create a dynamic group in Groups."
            : undefined,
        fetching: query.isFetching,
        onFirst: search.after ? () => search.goTo("") : undefined,
        onMore: last ? () => search.goTo(last) : undefined,
      })}
    >
      {selected.error ? <RpcError failure={toRpcFailure(selected.error)} /> : null}
    </SearchPicker>
  );
}
