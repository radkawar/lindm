import { create, toJsonString } from "@bufbuild/protobuf";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowUpRightIcon, Clock3Icon, InfoIcon, RefreshCwIcon } from "lucide-react";
import { DeviceState } from "../../../gen/lindm/admin/v1/admin_pb";
import { DeviceFilterSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { staleContactUntil, staleDevicesQueryOptions } from "./queries";

const lifecycleLabels: Record<DeviceState, string> = {
  [DeviceState.UNSPECIFIED]: "Unknown",
  [DeviceState.PENDING]: "Pending",
  [DeviceState.ACTIVE]: "Active",
  [DeviceState.REVOKED]: "Revoked",
  [DeviceState.RECOVERY_HOLD]: "Recovery hold",
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
            <h2>Stale devices</h2>
          </CardTitle>
          <Tooltip>
            <TooltipTrigger
              aria-label="About stale device previews"
              className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <InfoIcon className="size-3.5" aria-hidden="true" />
            </TooltipTrigger>
            <TooltipContent className="max-w-sm text-xs leading-relaxed">
              This separate, live inventory read shows the first five matches across all enrollment
              states, newest enrollment first, not oldest contact first. Missing contact is
              excluded. The fleet total is not calculated from these rows. Contacts can change after
              the aggregate was read, so this preview may differ from the summary. Refresh the
              overview to advance the cutoff; refreshing rows retains it.
            </TooltipContent>
          </Tooltip>
        </div>
        <CardDescription className="text-xs">
          Contact over {staleAfterSeconds / 3600} hours before the summary time.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">
            <span className="font-medium text-foreground tabular-nums">
              {staleTotal.toString()}
            </span>{" "}
            stale in fleet summary
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
            Refresh rows
          </Button>
        </div>
        {list.isPending ? <p role="status">Loading stale devices…</p> : null}
        {failure ? (
          <Alert variant="destructive">
            <AlertTitle>
              {failure.denied ? "Not authorized" : "Stale device list unavailable"}
            </AlertTitle>
            <AlertDescription>
              {failure.codeName}: {failure.message}
            </AlertDescription>
          </Alert>
        ) : null}
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
                      {device.hostname || device.id}
                    </Link>
                    <span className="text-xs text-muted-foreground">
                      Last contact {formatTimestamp(device.lastSeenAt).local}
                    </span>
                  </div>
                  <Badge variant="outline" className="shrink-0 text-xs">
                    {lifecycleLabels[device.lifecycleState] ?? "Unknown"}
                  </Badge>
                </li>
              ))}
            </ul>
            <p className="text-xs text-muted-foreground">
              Showing {data.devices.length}
              {data.nextPageToken ? " · More matches available" : " · No further matching page"}
            </p>
          </>
        ) : data ? (
          <div className="flex items-center gap-3 rounded-lg border border-dashed p-4">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
              <Clock3Icon className="size-4" aria-hidden="true" />
            </span>
            <div className="grid gap-1">
              <p className="text-sm font-medium">No matching devices</p>
              <p className="text-xs text-muted-foreground">
                No stale contacts matched this separate read.
              </p>
            </div>
          </div>
        ) : null}
        <Link
          to="/devices"
          search={{ pageSize: 50, pageToken: "", filter }}
          className="inline-flex items-center gap-1 text-xs font-medium text-foreground underline-offset-4 hover:underline"
        >
          Browse matching devices <ArrowUpRightIcon className="size-3.5" aria-hidden="true" />
        </Link>
      </CardContent>
    </Card>
  );
}
