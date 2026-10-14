// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import {
  CollectionStatus,
  type ModuleObservation,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ListPagination } from "@/components/ui/list-pagination";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
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
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { PAGE_SIZES, type PageSize } from "@/lib/list-search";
import type { PackageSearch } from "./package-search";
import { devicePackagesQueryOptions } from "./queries";
import { CollectionStatusBadge, Fact } from "./observations";
import { EmptyState } from "@/components/ui/empty-state";

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
  const pagination = useListPagination(search, (next) => onSearch({ ...search, ...next }));
  const pageToken = data?.pageToken;
  const freshResponse = packages.isFetchedAfterMount && !packages.isFetching;
  const filtered = search.manager !== "" || search.namePrefix !== "";
  // Module evidence only matters where a package is modular or its module
  // collection failed; unreported, not-applicable and non-modular rows would
  // fill a column with "Not reported" or "None".
  const showModules = (data?.packages ?? []).some(({ module }) =>
    module?.status === CollectionStatus.SUCCESS
      ? module.modular
      : module !== undefined &&
        module.status !== CollectionStatus.UNSPECIFIED &&
        module.status !== CollectionStatus.NOT_APPLICABLE,
  );

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
        <CardTitle>Installed packages</CardTitle>
        <CardDescription>From the device&apos;s latest package list.</CardDescription>
      </CardHeader>
      <CardContent className="flex min-w-0 flex-col gap-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <SuggestionPicker
            label="Package manager"
            field={SuggestionField.PACKAGE_MANAGER}
            deviceId={deviceId}
            placeholder="All managers"
            note="Package managers in this device's latest package list."
            value={search.manager}
            onChange={(manager) => onSearch({ ...search, manager, pageToken: "" })}
          />
          <SuggestionPicker
            label="Package name starts with"
            field={SuggestionField.PACKAGE_NAME}
            deviceId={deviceId}
            manager={search.manager || undefined}
            placeholder="All names"
            note="Names in this device's latest package list, 50 at a time. Choose “Use” to match every name starting with what you typed."
            allowTyped
            typedDescription="Every package name starting with this text"
            value={search.namePrefix}
            onChange={(namePrefix) => onSearch({ ...search, namePrefix, pageToken: "" })}
          />
        </div>
        <div>
          <Button variant="outline" disabled={packages.isFetching} onClick={latest}>
            Show latest list
          </Button>
        </div>
        {failure ? (
          <RpcError failure={failure} title="Couldn't load packages">
            <p>Choose Show latest list to try again.</p>
          </RpcError>
        ) : null}
        {packages.isPending ? <p role="status">Loading packages…</p> : null}
        {data ? (
          <>
            <TechnicalDetails
              items={[
                { label: "Snapshot ID", value: data.snapshotId },
                { label: "Sequence", value: data.sequence.toString() },
              ]}
            />
            {currentSnapshotSequence > data.sequence ? (
              <Alert>
                <AlertTitle>A newer package list is available</AlertTitle>
                <AlertDescription>Choose Show latest list to see it.</AlertDescription>
              </Alert>
            ) : null}
            {data.packages.length === 0 ? (
              <EmptyState
                title={filtered ? "No packages match these filters" : "This package list is empty"}
                description={
                  filtered
                    ? "Choose another name or package manager, or clear the filters."
                    : "The device reported no installed packages in this list."
                }
                action={
                  filtered ? (
                    <Button
                      variant="outline"
                      onClick={() =>
                        onSearch({ ...search, manager: "", namePrefix: "", pageToken: "" })
                      }
                    >
                      Clear filters
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Architecture</TableHead>
                    <TableHead>Manager</TableHead>
                    <TableHead>Source package</TableHead>
                    {showModules ? <TableHead>Module</TableHead> : null}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.packages.map((record) => (
                    <TableRow key={`${data.snapshotId}:${record.position}`}>
                      <TableCell className="font-medium">{record.name}</TableCell>
                      <TableCell className="font-mono text-xs">{record.version}</TableCell>
                      <TableCell>{record.architecture || "Not reported"}</TableCell>
                      <TableCell>{record.manager}</TableCell>
                      <TableCell>
                        {record.sourceName ? (
                          <>
                            {record.sourceName}{" "}
                            <span className="font-mono text-xs">{record.sourceVersion}</span>
                          </>
                        ) : (
                          "Not reported"
                        )}
                      </TableCell>
                      {showModules ? (
                        <TableCell className="whitespace-normal">
                          <PackageModuleEvidence module={record.module} />
                        </TableCell>
                      ) : null}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        ) : null}
        <ListPagination
          label="Package pages"
          previousLabel="Previous page"
          onPrevious={
            pagination.previousLabel === "Previous page" ? pagination.previous : undefined
          }
          onNext={
            data?.nextPageToken ? () => pagination.next(data?.nextPageToken ?? "") : undefined
          }
          busy={packages.isFetching}
          pageSize={search.pageSize}
          pageSizes={PAGE_SIZES}
          onPageSizeChange={(size) => onSearch({ ...search, pageSize: size as PageSize })}
        />
      </CardContent>
    </Card>
  );
}

function PackageModuleEvidence({ module }: { module: ModuleObservation | undefined }) {
  if (!module || module.status !== CollectionStatus.SUCCESS) {
    return <CollectionStatusBadge status={module?.status} />;
  }
  if (!module.modular) return <span>None</span>;
  return (
    <dl className="grid gap-2">
      <Fact label="Module name">{module.name}</Fact>
      <Fact label="Stream">{module.stream}</Fact>
      <Fact label="Module version">{module.version}</Fact>
      <Fact label="Context">{module.context}</Fact>
    </dl>
  );
}
