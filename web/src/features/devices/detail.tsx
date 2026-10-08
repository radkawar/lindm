import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { ReactNode } from "react";
import {
  CollectionStatus,
  SnapshotState,
  type ObservedString,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { DeviceLifecycleBadge } from "./lifecycle-badge";
import { DevicePackages } from "./packages";
import type { PackageSearch } from "./package-search";
import { deviceQueryOptions } from "./queries";

const collectionLabels: Record<CollectionStatus, string> = {
  [CollectionStatus.UNSPECIFIED]: "Not reported",
  [CollectionStatus.SUCCESS]: "Successful collection",
  [CollectionStatus.UNAVAILABLE]: "Unavailable",
  [CollectionStatus.PERMISSION_DENIED]: "Permission denied",
  [CollectionStatus.TIMEOUT]: "Collection timed out",
  [CollectionStatus.INVALID_OUTPUT]: "Invalid native output",
  [CollectionStatus.CAPACITY_EXCEEDED]: "Collection capacity exceeded",
  [CollectionStatus.NATIVE_COMMAND_FAILURE]: "Native command failed",
};

const snapshotLabels: Record<SnapshotState, string> = {
  [SnapshotState.UNSPECIFIED]: "Not reported",
  [SnapshotState.STAGING]: "Upload in progress — not published",
  [SnapshotState.COMMITTED]: "Published",
  [SnapshotState.SUPERSEDED]: "Superseded",
  [SnapshotState.EXPIRED]: "Expired",
};

export function DeviceDetailView({
  deviceId,
  search,
  onSearch,
}: {
  deviceId: string;
  search: PackageSearch;
  onSearch: (next: PackageSearch, replace?: boolean) => void;
}) {
  const lifetime = useAuthLifetime();
  const detail = useQuery(deviceQueryOptions(lifetime, deviceId));
  const failure = detail.error ? toRpcFailure(detail.error) : null;
  const data = failure ? undefined : detail.data;
  const device = data?.device;
  const host = data?.host?.observation;
  const attempt = data?.packageAttempt;
  const snapshot = data?.currentSnapshot;
  return (
    <section className="flex min-w-0 flex-col gap-4" aria-busy={detail.isFetching}>
      <Link
        to="/devices"
        search={{ pageSize: 50, pageToken: "" }}
        className="w-fit text-sm underline underline-offset-4"
      >
        Back to devices
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="break-words text-2xl font-semibold">
            {device?.hostname.trim() || "Device inventory"}
          </h1>
          <p className="break-all font-mono text-xs text-muted-foreground">{deviceId}</p>
        </div>
        <Button
          variant="outline"
          disabled={detail.isFetching}
          onClick={() => void detail.refetch()}
        >
          Refresh device
        </Button>
      </div>
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>{failure.denied ? "Not authorized" : "Device detail unavailable"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      {detail.isPending ? <p role="status">Loading device inventory…</p> : null}
      {device ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Identity and contact</CardTitle>
              <CardDescription>
                Contact is not inventory freshness, online presence, or compliance.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Fact label="Lifecycle">
                  <DeviceLifecycleBadge state={device.lifecycleState} />
                </Fact>
                <Fact label="Last contact (server)">
                  <ObservedTime value={device.lastSeenAt} />
                </Fact>
                <Fact label="Host sequence">{device.hostSequence.toString()}</Fact>
                <Fact label="Package attempt sequence">{device.packageSequence.toString()}</Fact>
                <Fact label="Published snapshot sequence">
                  {device.publishedSnapshotSequence.toString()}
                </Fact>
              </dl>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Host observations</CardTitle>
              <CardDescription>
                Collection times and values are device-reported. Missing or failed fields are not
                successful empty values.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {host ? (
                <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <Fact label="Collection started (device)">
                    <ObservedTime value={host.startedAt} />
                  </Fact>
                  <Fact label="Collection finished (device)">
                    <ObservedTime value={host.finishedAt} />
                  </Fact>
                  <Fact label="Received (server)">
                    <ObservedTime value={data?.host?.receivedAt} />
                  </Fact>
                  <Fact label="Hostname">
                    <ObservedValue field={host.hostname} />
                  </Fact>
                  <Fact label="Operating system">
                    <ObservedValue field={host.osId} />
                  </Fact>
                  <Fact label="OS version">
                    <ObservedValue field={host.osVersion} />
                  </Fact>
                  <Fact label="Architecture">
                    <ObservedValue field={host.architecture} />
                  </Fact>
                  <Fact label="Kernel">
                    <ObservedValue field={host.kernelRelease} />
                  </Fact>
                  <Fact label="Boot ID">
                    <ObservedValue field={host.bootId} />
                  </Fact>
                  <Fact label="Hardware vendor">
                    <ObservedValue field={host.hardwareVendor} />
                  </Fact>
                  <Fact label="Hardware model">
                    <ObservedValue field={host.hardwareModel} />
                  </Fact>
                  <Fact label="Hardware serial">
                    <ObservedValue field={host.hardwareSerial} />
                  </Fact>
                </dl>
              ) : (
                <p>No host observation has been accepted.</p>
              )}
            </CardContent>
          </Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Latest completed package attempt</CardTitle>
                <CardDescription>
                  A failed collection preserves the last published inventory and its original
                  freshness.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {attempt ? (
                  <dl className="grid gap-4 sm:grid-cols-2">
                    <Fact label="Result">
                      <Badge
                        variant={
                          attempt.status === CollectionStatus.SUCCESS ? "outline" : "destructive"
                        }
                      >
                        {collectionLabels[attempt.status] ?? "Unknown collection status"}
                      </Badge>
                    </Fact>
                    <Fact label="Sequence">{attempt.sequence.toString()}</Fact>
                    <Fact label="Backend">{attempt.backend || "Not reported"}</Fact>
                    <Fact label="Collection started (device)">
                      <ObservedTime value={attempt.startedAt} />
                    </Fact>
                    <Fact label="Collection finished (device)">
                      <ObservedTime value={attempt.finishedAt} />
                    </Fact>
                    <Fact label="Received (server)">
                      <ObservedTime value={attempt.receivedAt} />
                    </Fact>
                  </dl>
                ) : (
                  <p>No completed package attempt has been accepted.</p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Latest published package inventory</CardTitle>
                <CardDescription>
                  Only a complete committed snapshot is inventory. Partial uploads are never shown
                  as complete.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {snapshot ? (
                  <dl className="grid gap-4 sm:grid-cols-2">
                    <Fact label="State">
                      {snapshotLabels[snapshot.state] ?? "Unknown snapshot state"}
                    </Fact>
                    <Fact label="Packages">{snapshot.packageCount.toLocaleString()}</Fact>
                    <Fact label="Snapshot ID">
                      <span className="break-all font-mono text-xs">{snapshot.snapshotId}</span>
                    </Fact>
                    <Fact label="Sequence">{snapshot.sequence.toString()}</Fact>
                    <Fact label="Collection finished (device)">
                      <ObservedTime value={snapshot.finishedAt} />
                    </Fact>
                    <Fact label="Published (server)">
                      <ObservedTime value={snapshot.committedAt} />
                    </Fact>
                    {!snapshot.packagesAvailable ? (
                      <Fact label="Package rows">
                        No longer retained; the manifest count is not an empty collection.
                      </Fact>
                    ) : null}
                  </dl>
                ) : (
                  <p>No complete package snapshot has been published.</p>
                )}
              </CardContent>
            </Card>
          </div>
          {data?.stagingSnapshot ? (
            <Alert>
              <AlertTitle>Package upload in progress</AlertTitle>
              <AlertDescription>
                Snapshot {data.stagingSnapshot.snapshotId}, sequence{" "}
                {data.stagingSnapshot.sequence.toString()}, is staging. It has not replaced the
                published inventory.
              </AlertDescription>
            </Alert>
          ) : null}
          {snapshot || search.pageToken !== "" ? (
            <DevicePackages
              key={`${deviceId}:${search.manager}:${search.namePrefix}`}
              deviceId={deviceId}
              currentSnapshotSequence={snapshot?.sequence ?? 0n}
              search={search}
              onSearch={onSearch}
            />
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="mb-1 text-sm text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm">{children}</dd>
    </div>
  );
}

function ObservedValue({ field }: { field: ObservedString | undefined }) {
  if (!field) return <span className="text-muted-foreground">Not reported</span>;
  return field.status === CollectionStatus.SUCCESS ? (
    <span>{field.value}</span>
  ) : (
    <span className="text-muted-foreground">
      {collectionLabels[field.status] ?? "Unknown collection status"}
    </span>
  );
}

export function ObservedTime({ value }: { value: Timestamp | undefined }) {
  const formatted = formatTimestamp(value);
  return formatted.date ? (
    <time dateTime={formatted.utc} title={formatted.utc}>
      {formatted.local}
    </time>
  ) : (
    <span className="text-muted-foreground">{formatted.local}</span>
  );
}
