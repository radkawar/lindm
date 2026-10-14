// SPDX-License-Identifier: Apache-2.0

import { useDeferredValue, useState } from "react";
import { keepPreviousData, queryOptions, useQuery } from "@tanstack/react-query";
import { SearchPicker, pickerFooter, type PickerProps } from "@/components/ui/search-picker";
import { Button } from "@/components/ui/button";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { SEARCH_DELAY_MS, useDelayed } from "@/hooks/use-delayed";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";
import { toRpcFailure } from "@/lib/errors";
import { deviceOsLabel } from "./os";
import { deviceQueryOptions, devicesQueryOptions } from "./queries";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";

// A page of up to 100 device groups whose names contain nameSearch (any case).
function devicePickerGroupsQueryOptions(
  lifetime: AuthLifetime,
  nameSearch: string,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["device-picker-groups", lifetime.generation, nameSearch, pageToken],
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: ({ signal }) =>
      adminClient.listDeviceGroups(
        { pageSize: 100, nameSearch, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}

// One device group by ID wherever it sorts; null when it no longer exists.
function devicePickerGroupQueryOptions(lifetime: AuthLifetime, groupId: string) {
  return queryOptions({
    queryKey: ["device-picker-groups", lifetime.generation, "lookup", groupId],
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listDeviceGroups(
        { groupIds: [groupId] },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      return result.groups.find((item) => item.id === groupId) ?? null;
    },
  });
}

// The device filter's group choice; the server searches every group by name.
function DeviceGroupFilterPicker(props: PickerProps) {
  const lifetime = useAuthLifetime();
  const [search, setSearch] = useState("");
  const typed = search.trim().slice(0, 128);
  const nameSearch = useDelayed(typed, SEARCH_DELAY_MS);
  const [page, setPage] = useState({ nameSearch: "", token: "" });
  const pageToken = page.nameSearch === nameSearch ? page.token : "";
  const query = useQuery({
    ...devicePickerGroupsQueryOptions(lifetime, nameSearch, pageToken),
    placeholderData: keepPreviousData,
  });
  const groups = query.error ? [] : (query.data?.groups ?? []);
  const selected = useQuery({
    ...devicePickerGroupQueryOptions(lifetime, props.value),
    enabled: !!props.value && !!query.data && !groups.some((item) => item.id === props.value),
  });
  const options = groups.map((item) => ({ value: item.id, label: item.name }));
  if (selected.data && !options.some((option) => option.value === selected.data?.id))
    options.unshift({ value: selected.data.id, label: selected.data.name });
  const settled = !query.isFetching && nameSearch === typed;
  const nextPageToken = query.data?.nextPageToken ?? "";
  return (
    <SearchPicker
      {...props}
      placeholder="Any group"
      search={search}
      onSearchChange={setSearch}
      options={options}
      note="Type any part of a group name. Up to 100 groups at a time."
      footer={pickerFooter({
        loading: query.isPending,
        error: query.error,
        onRetry: () => void query.refetch(),
        empty:
          query.isSuccess && settled && groups.length === 0
            ? nameSearch
              ? `No device group names contain “${nameSearch}”.`
              : "No device groups yet."
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

export function DevicePicker({
  selectionValue,
  ...props
}: PickerProps & { selectionValue?: (device: Device) => string }) {
  const lifetime = useAuthLifetime();
  const canReadGroups = canPermission(usePrincipal(), "accounts.manage", true);
  const [search, setSearch] = useState("");
  const [os, setOS] = useState("");
  const [group, setGroup] = useState("");
  const [cursor, setCursor] = useState({ filter: "", token: "" });
  const hostnameSearch = useDeferredValue(search.trim().slice(0, 253));
  const filter = useDeferredValue(JSON.stringify({ osId: os }));
  // Paging restarts whenever the OS or the hostname text changes.
  const key = `${filter}\n${hostnameSearch}`;
  const query = useQuery(
    devicesQueryOptions(lifetime, {
      pageSize: 100,
      pageToken: cursor.filter === key ? cursor.token : "",
      filter,
      hostnameSearch,
    }),
  );
  const selected = useQuery({
    ...deviceQueryOptions(lifetime, props.value),
    enabled: !!props.value,
  });
  // The first 100 groups name each device's groups; the filter looks its group up.
  const groups = useQuery({
    ...devicePickerGroupsQueryOptions(lifetime, "", ""),
    enabled: canReadGroups,
  });
  const selectedGroup = useQuery({
    ...devicePickerGroupQueryOptions(lifetime, group),
    enabled: canReadGroups && !!group,
  });
  const devices = (query.data?.devices ?? []).filter(
    (device) => !group || selectedGroup.data?.deviceIds.includes(device.id),
  );
  if (selected.data?.device && !devices.some((device) => device.id === props.value))
    devices.unshift(selected.data.device);
  return (
    <div className="grid gap-2">
      <SearchPicker
        {...props}
        onChange={(next) => {
          const device = devices.find((item) => item.id === next);
          props.onChange(device && selectionValue ? selectionValue(device) : next);
        }}
        search={search}
        onSearchChange={setSearch}
        options={devices.map((device) => ({
          value: device.id,
          label: device.hostname.trim() || "Unnamed device",
          description: [
            deviceOsLabel(device),
            ...(groups.data?.groups
              .filter((item) => item.deviceIds.includes(device.id))
              .map((item) => item.name) ?? []),
          ]
            .filter(Boolean)
            .join(" · "),
        }))}
        note="Showing up to 100 devices per page. Hostname prefix and operating system search the server; group narrows this page."
        footer={
          query.isPending || query.error || cursor.token || query.data?.nextPageToken ? (
            <>
              {query.isPending ? (
                <p role="status" className="text-xs text-muted-foreground">
                  Loading devices…
                </p>
              ) : null}
              {query.error ? (
                <RpcError failure={toRpcFailure(query.error)}>
                  <Button type="button" variant="outline" onClick={() => void query.refetch()}>
                    Retry devices
                  </Button>
                </RpcError>
              ) : null}
              {cursor.token || query.data?.nextPageToken ? (
                <div className="flex flex-wrap gap-2">
                  {cursor.token ? (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={props.disabled || query.isFetching}
                      onClick={() => setCursor({ filter: key, token: "" })}
                    >
                      First devices
                    </Button>
                  ) : null}
                  {query.data?.nextPageToken ? (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={props.disabled || query.isFetching}
                      onClick={() =>
                        setCursor({ filter: key, token: query.data?.nextPageToken ?? "" })
                      }
                    >
                      More devices
                    </Button>
                  ) : null}
                </div>
              ) : null}
            </>
          ) : undefined
        }
      >
        {selected.error ? <RpcError failure={toRpcFailure(selected.error)} /> : null}
      </SearchPicker>
      <details>
        <summary className="cursor-pointer text-xs text-muted-foreground">Filter devices</summary>
        <div className="mt-2 grid gap-2">
          <SuggestionPicker
            label="Operating system"
            field={SuggestionField.OS_ID}
            placeholder="Any operating system"
            note="Operating systems your devices report."
            value={os}
            onChange={setOS}
            disabled={props.disabled}
          />
          {groups.error ? <RpcError failure={toRpcFailure(groups.error)} /> : null}
          {selectedGroup.error ? <RpcError failure={toRpcFailure(selectedGroup.error)} /> : null}
          {canReadGroups ? (
            <DeviceGroupFilterPicker
              label="Device group"
              value={group}
              onChange={setGroup}
              disabled={props.disabled}
            />
          ) : null}
        </div>
      </details>
    </div>
  );
}

export function DeviceBindingPicker(props: PickerProps) {
  const binding: { deviceId?: string } = props.value ? JSON.parse(props.value) : {};
  return (
    <DevicePicker
      {...props}
      value={binding.deviceId ?? ""}
      selectionValue={(device) =>
        JSON.stringify({ deviceId: device.id, enrollmentGeneration: device.enrollmentGeneration })
      }
    />
  );
}
