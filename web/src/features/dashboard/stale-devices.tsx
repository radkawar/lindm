import { create, toJsonString } from "@bufbuild/protobuf";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowUpRightIcon, RefreshCwIcon } from "lucide-react";
import { DeviceState } from "../../../gen/lindm/admin/v1/admin_pb";
import { DeviceFilterSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { staleContactUntil, staleDevicesQueryOptions } from "./queries";

const lifecycleLabels: Record<DeviceState, string> = {
  [DeviceState.UNSPECIFIED]: "Unknown",
  [DeviceState.PENDING]: "Waiting to enroll",
  [DeviceState.ACTIVE]: "Enrolled",
  [DeviceState.REVOKED]: "Revoked",
  [DeviceState.RECOVERY_HOLD]: "Recovery hold",
};

const lifecycleTones: Record<DeviceState, StatusTone> = {
  [DeviceState.UNSPECIFIED]: "neutral",
  [DeviceState.PENDING]: "warning",
  [DeviceState.ACTIVE]: "success",
  [DeviceState.REVOKED]: "destructive",
  [DeviceState.RECOVERY_HOLD]: "warning",
};

export function StaleDevices({
  observedAt,
  staleAfterSeconds,
  staleTotal,
}: {
  observedAt: Timestamp;
  staleAfterSeconds: number;
  staleTotal: bigint;
}) {
  const lifetime = useAuthLifetime();
  const lastSeenUntil = staleContactUntil(observedAt, staleAfterSeconds);
  const list = useQuery(staleDevicesQueryOptions(lifetime, lastSeenUntil));
  const failure = list.error ? toRpcFailure(list.error) : null;
  const data = failure ? undefined : list.data;
  const filter = toJsonString(DeviceFilterSchema, create(DeviceFilterSchema, { lastSeenUntil }));

  return (
    <section
      className="grid min-w-0 gap-3 border-l pl-3"
      aria-busy={list.isFetching}
      data-review-metric=""
    >
      <h4 className="text-sm font-semibold">Stale contact preview</h4>
      <p className="text-xs text-muted-foreground">
        This live list shows up to five devices in enrollment order. It excludes devices that never
        checked in. The list can differ from the dashboard snapshot.
      </p>
      <div className="grid gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">
            <span className="font-medium text-foreground tabular-nums">
              {staleTotal.toString()}
            </span>{" "}
            devices at the dashboard snapshot, last seen over {staleAfterSeconds / 3600} hours ago.
            Refresh the dashboard to update the cutoff.
          </p>
          <Button
            variant="outline"
            disabled={list.isFetching}
            onClick={() => {
              if (!lifetime.signal.aborted) void list.refetch();
            }}
          >
            <RefreshCwIcon aria-hidden="true" />
            {list.isFetching ? "Refreshing…" : "Refresh list"}
          </Button>
        </div>
        {list.isPending ? <p role="status">Loading…</p> : null}
        {failure ? <RpcError failure={failure} title="Couldn't load this list" /> : null}
        {data?.devices.length ? (
          <>
            <ul className="divide-y">
              {data.devices.map((device) => (
                <li
                  key={device.id}
                  className="flex flex-wrap items-start justify-between gap-3 py-2 first:pt-0 last:pb-0"
                >
                  <div className="grid min-w-0 flex-1 gap-1">
                    <Link
                      to="/devices/$deviceId"
                      params={{ deviceId: device.id }}
                      className="break-words text-sm font-medium text-foreground underline underline-offset-4 hover:decoration-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      {device.hostname.trim() || "Unnamed device"}
                    </Link>
                    <span className="text-xs text-muted-foreground">
                      Last check-in {formatTimestamp(device.lastSeenAt).local}
                    </span>
                  </div>
                  <StatusBadge status={lifecycleTones[device.lifecycleState] ?? "neutral"} dot>
                    {lifecycleLabels[device.lifecycleState] ?? "Unknown"}
                  </StatusBadge>
                </li>
              ))}
            </ul>
            <p className="text-xs text-muted-foreground">
              Showing {data.devices.length}
              {data.nextPageToken ? ". More devices match." : "."}
            </p>
          </>
        ) : data ? (
          <EmptyState
            title="No devices match this stale-contact cutoff"
            description="This live preview excludes devices with no recorded check-in. It is not a fleet health assessment."
          />
        ) : null}
        <Link
          to="/devices"
          search={{ pageSize: 50, pageToken: "", filter }}
          className="inline-flex min-h-8 items-center gap-1 text-sm font-medium text-foreground underline underline-offset-4 hover:decoration-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          Open filtered device list <ArrowUpRightIcon className="size-4" aria-hidden="true" />
        </Link>
      </div>
    </section>
  );
}
