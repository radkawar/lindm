import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  CollectionStatus,
  type ModuleObservation,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useListPagination } from "@/hooks/use-list-pagination";
import { toRpcFailure } from "@/lib/errors";
import { PAGE_SIZES, type PageSize } from "@/lib/list-search";
import { formatTimestamp } from "@/lib/time";
import type { PackageSearch } from "./package-search";
import { devicePackagesQueryOptions } from "./queries";
import { collectionLabels, Fact } from "./observations";

export function DevicePackages({
  deviceId,
  currentSnapshotSequence,
  search,
  onSearch,
}: {
  deviceId: string;
  currentSnapshotSequence: bigint;
  search: PackageSearch;
  onSearch: (next: PackageSearch, replace?: boolean) => void;
}) {
  const lifetime = useAuthLifetime();
  const packages = useQuery(devicePackagesQueryOptions(lifetime, deviceId, search));
  const failure = packages.error ? toRpcFailure(packages.error) : null;
  const data = failure ? undefined : packages.data;
  const [manager, setManager] = useState(search.manager);
  const [namePrefix, setNamePrefix] = useState(search.namePrefix);
  const pagination = useListPagination(search, (next) => onSearch({ ...search, ...next }));
  const expiry = formatTimestamp(data?.cursorExpiresAt);
  const pageToken = data?.pageToken;
  const freshResponse = packages.isFetchedAfterMount && !packages.isFetching;

  useEffect(() => {
    // The first response must also become an immutable cursor. Re-fetching an
    // empty token on Previous/focus would otherwise silently select newer data.
    if (
      !failure &&
      freshResponse &&
      search.pageToken === "" &&
      pageToken &&
      !lifetime.signal.aborted
    ) {
      onSearch({ ...search, pageToken }, true);
    }
  }, [failure, freshResponse, search, pageToken, lifetime, onSearch]);

  function latest() {
    if (search.pageToken === "") void packages.refetch();
    else onSearch({ ...search, pageToken: "" });
  }

  return (
    <Card aria-busy={packages.isFetching}>
      <CardHeader>
        <CardTitle>Package records</CardTitle>
        <CardDescription>
          Every page is pinned to one complete snapshot. A view expires after 15 minutes; refreshing
          a page does not extend it. Module identity is native package evidence, never inferred from
          repository IDs.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex min-w-0 flex-col gap-4">
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            onSearch({ ...search, manager, namePrefix, pageToken: "" });
            if (
              search.pageToken === "" &&
              manager === search.manager &&
              namePrefix === search.namePrefix
            )
              void packages.refetch();
          }}
        >
          <div className="grid min-w-0 gap-1.5">
            <Label htmlFor="package-manager">Manager for new view</Label>
            <Input
              id="package-manager"
              value={manager}
              onChange={(event) => setManager(event.target.value)}
              maxLength={64}
              placeholder="All managers"
            />
          </div>
          <div className="grid min-w-0 gap-1.5">
            <Label htmlFor="package-prefix">Name prefix for new view</Label>
            <Input
              id="package-prefix"
              value={namePrefix}
              onChange={(event) => setNamePrefix(event.target.value)}
              maxLength={512}
              placeholder="All names"
            />
          </div>
          <Button type="submit">Apply to latest snapshot</Button>
        </form>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            disabled={packages.isFetching}
            onClick={() => void packages.refetch()}
          >
            Refresh this page
          </Button>
          <Button variant="outline" disabled={packages.isFetching} onClick={latest}>
            Latest snapshot
          </Button>
          <Label htmlFor="package-page-size">Page size</Label>
          <SelectField
            id="package-page-size"
            value={search.pageSize}
            onValueChange={(value) => {
              onSearch({ ...search, pageSize: Number(value) as PageSize });
            }}
            options={PAGE_SIZES.map((size) => ({ value: size, label: size }))}
          />
        </div>
        {failure ? (
          <Alert variant="destructive">
            <AlertTitle>
              {failure.denied ? "Not authorized" : "Package view unavailable"}
            </AlertTitle>
            <AlertDescription>
              {failure.codeName}: {failure.message}. Expired or unavailable snapshots are not
              replaced silently. Choose Latest snapshot to start a new view.
            </AlertDescription>
          </Alert>
        ) : null}
        {packages.isPending ? <p role="status">Loading package records…</p> : null}
        {data ? (
          <>
            <div className="grid gap-1 text-sm text-muted-foreground">
              <p className="break-all">
                Viewing snapshot <span className="font-mono text-xs">{data.snapshotId}</span>,
                sequence {data.sequence.toString()}.
              </p>
              <p>
                View expires:{" "}
                {expiry.date ? (
                  <time dateTime={expiry.utc} title={expiry.utc}>
                    {expiry.local}
                  </time>
                ) : (
                  expiry.local
                )}
                .
              </p>
            </div>
            {currentSnapshotSequence > data.sequence ? (
              <Alert>
                <AlertTitle>A newer published snapshot is available</AlertTitle>
                <AlertDescription>
                  This table remains on its original snapshot. Choose Latest snapshot to switch
                  explicitly.
                </AlertDescription>
              </Alert>
            ) : null}
            {data.packages.length === 0 ? (
              <p>
                No package rows match this view. This does not change the snapshot's recorded
                package count.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Version (including epoch)</TableHead>
                    <TableHead>Architecture</TableHead>
                    <TableHead>Manager</TableHead>
                    <TableHead>Native source package</TableHead>
                    <TableHead>Native module evidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.packages.map((record) => (
                    <TableRow key={`${data.snapshotId}:${record.position}`}>
                      <TableCell className="font-medium">{record.name}</TableCell>
                      <TableCell className="font-mono text-xs">{record.version}</TableCell>
                      <TableCell>
                        {record.architecture || "Not recorded by native metadata"}
                      </TableCell>
                      <TableCell>{record.manager}</TableCell>
                      <TableCell>
                        {record.sourceName
                          ? `${record.sourceName} ${record.sourceVersion}`
                          : "Not recorded by native metadata"}
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <PackageModuleEvidence module={record.module} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        ) : null}
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            disabled={pagination.previousLabel !== "Previous page" || packages.isFetching}
            onClick={pagination.previous}
          >
            Previous page
          </Button>
          <Button
            variant="outline"
            disabled={!data?.nextPageToken || packages.isFetching}
            onClick={() => pagination.next(data?.nextPageToken ?? "")}
          >
            Next page
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function PackageModuleEvidence({ module }: { module: ModuleObservation | undefined }) {
  if (!module) return <span className="text-muted-foreground">Unknown — not reported</span>;
  if (module.status !== CollectionStatus.SUCCESS) {
    return (
      <span className="text-muted-foreground">
        {collectionLabels[module.status] ?? "Unknown collection status"}
      </span>
    );
  }
  if (!module.modular) return <span>Not modular (native observation)</span>;
  return (
    <dl className="grid gap-2">
      <Fact label="Module name">{module.name}</Fact>
      <Fact label="Stream">{module.stream}</Fact>
      <Fact label="Module version">{module.version}</Fact>
      <Fact label="Context">{module.context}</Fact>
    </dl>
  );
}
