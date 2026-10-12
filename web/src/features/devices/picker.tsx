import { useDeferredValue, useState } from "react";
import { queryOptions, useQuery } from "@tanstack/react-query";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";
import { toRpcFailure } from "@/lib/errors";
import { deviceQueryOptions, devicesQueryOptions } from "./queries";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";

function devicePickerGroupsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["device-picker-groups", lifetime.generation],
    meta: { authGeneration: lifetime.generation },
    retry: false,
    queryFn: ({ signal }) =>
      adminClient.listDeviceGroups(
        { pageSize: 100 },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
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
  const groups = useQuery({ ...devicePickerGroupsQueryOptions(lifetime), enabled: canReadGroups });
  const selectedGroup = groups.data?.groups.find((item) => item.id === group);
  const devices = (query.data?.devices ?? []).filter(
    (device) => !group || selectedGroup?.deviceIds.includes(device.id),
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
            device.osId,
            device.osVersion,
            ...(groups.data?.groups
              .filter((item) => item.deviceIds.includes(device.id))
              .map((item) => item.name) ?? []),
          ]
            .filter(Boolean)
            .join(" · "),
        }))}
        note="Showing up to 100 devices per page. Hostname prefix and operating system search the server; group narrows this page."
      >
        {query.isPending ? <p role="status">Loading devices…</p> : null}
        {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
        {selected.error ? <RpcError failure={toRpcFailure(selected.error)} /> : null}
      </SearchPicker>
      <details>
        <summary className="cursor-pointer text-xs text-muted-foreground">Filter devices</summary>
        <div className="mt-2 grid gap-2">
          <label className="grid gap-1 text-sm">
            Operating system
            <Input
              value={os}
              onChange={(event) => setOS(event.target.value)}
              disabled={props.disabled}
              placeholder="For example, ubuntu"
            />
          </label>
          {groups.error ? <RpcError failure={toRpcFailure(groups.error)} /> : null}
          {canReadGroups ? (
            <SearchPicker
              label="Device group"
              value={group}
              onChange={setGroup}
              disabled={props.disabled}
              options={(groups.data?.groups ?? []).map((item) => ({
                value: item.id,
                label: item.name,
              }))}
              note="Showing the first 100 groups."
            />
          ) : null}
        </div>
      </details>
      <div className="flex gap-2">
        {cursor.token ? (
          <Button
            type="button"
            variant="outline"
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
            disabled={props.disabled || query.isFetching}
            onClick={() => setCursor({ filter: key, token: query.data?.nextPageToken ?? "" })}
          >
            More devices
          </Button>
        ) : null}
      </div>
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
