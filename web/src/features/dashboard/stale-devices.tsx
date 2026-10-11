import { create, toJsonString } from "@bufbuild/protobuf";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowUpRightIcon, InfoIcon, RefreshCwIcon } from "lucide-react";
import { DeviceState } from "../../../gen/lindm/admin/v1/admin_pb";
import { DeviceFilterSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
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
    <Card className="min-w-0" aria-busy={list.isFetching}>
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <CardTitle>
            <h2>Devices not seen recently</h2>
          </CardTitle>
          <Tooltip>
            <TooltipTrigger
              aria-label="About this list"
              className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <InfoIcon className="size-3.5" aria-hidden="true" />
            </TooltipTrigger>
            <TooltipContent className="max-w-sm text-xs leading-relaxed">
              Shows up to five devices. Devices that never checked in are not listed. Refresh the
              dashboard to update the cutoff time.
            </TooltipContent>
          </Tooltip>
        </div>
        <CardDescription className="text-xs">
          No check-in for over {staleAfterSeconds / 3600} hours.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">
            <span className="font-medium text-foreground tabular-nums">
              {staleTotal.toString()}
            </span>{" "}
            in total
          </p>
          <Button
            variant="outline"
            size="sm"
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
                  className="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0"
                >
                  <div className="grid min-w-0 gap-1">
                    <Link
                      to="/devices/$deviceId"
                      params={{ deviceId: device.id }}
                      search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                      className="truncate text-sm font-medium underline-offset-4 hover:underline"
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
            title="All devices checked in recently"
            description="No device has gone quiet past the cutoff."
          />
        ) : null}
        <Link
          to="/devices"
          search={{ pageSize: 50, pageToken: "", filter }}
          className="inline-flex items-center gap-1 text-xs font-medium text-foreground underline-offset-4 hover:underline"
        >
          View all <ArrowUpRightIcon className="size-3.5" aria-hidden="true" />
        </Link>
      </CardContent>
    </Card>
  );
}
