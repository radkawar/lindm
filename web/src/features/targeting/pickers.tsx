import { createContext, useContext, type ReactNode } from "react";
import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import type { RolloutState } from "../../../gen/lindm/admin/v1/targeting_pb";
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
import {
  dynamicGroupQueryOptions,
  dynamicGroupsQueryOptions,
  rolloutsQueryOptions,
} from "./queries";

const Context = createContext<TargetPickers | null>(null);
export function TargetPickerProvider({
  pickers,
  children,
}: {
  pickers: TargetPickers;
  children: ReactNode;
}) {
  return <Context value={pickers}>{children}</Context>;
}
export function useTargetPickers() {
  const pickers = useContext(Context);
  if (!pickers) throw new Error("Targeting pickers must be composed by the route.");
  return pickers;
}
export type TargetPickers = {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
  profileRevisionPicker: PickerSlot;
};
// Read-only names for saved records, composed by the route like the pickers.
export type NameSlot = (props: { value: string }) => ReactNode;
export type TargetNames = {
  deviceName: NameSlot;
  groupName: NameSlot;
  profileVersionName: NameSlot;
};

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
// A rollout has no name of its own; its stage names identify it everywhere.
export function rolloutName(state: RolloutState) {
  return state.rollout?.rings.map((ring) => ring.name).join(", ") || "Unnamed rollout";
}

// The server searches every rollout by any part of its name (its stage names).
export function RolloutPicker(props: PickerProps) {
  const search = useServerSearch();
  const query = useQuery({
    ...rolloutsQueryOptions(useAuthLifetime(), search.after, search.nameSearch),
    placeholderData: keepPreviousData,
  });
  const rollouts = query.error ? [] : (query.data ?? []);
  const settled = !query.isFetching && search.nameSearch === search.typed;
  const last = rollouts.length === PAGE_SIZE ? (rollouts.at(-1)?.rollout?.rolloutId ?? "") : "";
  return (
    <SearchPicker
      {...props}
      search={search.search}
      onSearchChange={search.setSearch}
      options={rollouts.flatMap((state) =>
        state.rollout
          ? [
              {
                value: state.rollout.rolloutId,
                label: rolloutName(state),
                description: state.paused ? "Paused" : "In progress",
              },
            ]
          : [],
      )}
      note="Type any part of a stage name. Up to 100 rollouts at a time."
      footer={pickerFooter({
        loading: query.isPending,
        error: query.error,
        onRetry: () => void query.refetch(),
        empty:
          query.isSuccess && settled && rollouts.length === 0
            ? search.nameSearch
              ? `No staged rollouts have a stage name containing “${search.nameSearch}”.`
              : "No staged rollouts yet. Leave this optional selection empty, or plan one under Staged rollouts above."
            : undefined,
        fetching: query.isFetching,
        onFirst: search.after ? () => search.goTo("") : undefined,
        onMore: last ? () => search.goTo(last) : undefined,
      })}
    />
  );
}
