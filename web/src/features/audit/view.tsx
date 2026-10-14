// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { ListPagination } from "@/components/ui/list-pagination";
import type { PickerSlot } from "@/components/ui/search-picker";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { PAGE_SIZES } from "@/lib/list-search";
import { canPermission } from "@/lib/permissions";
import { auditActionLabel } from "./actions";
import { auditQueryOptions } from "./queries";
import { AuditExport } from "./export";
import { AuditFilters } from "./filters";
import { DEFAULT_AUDIT_VIEW, type AuditSearch } from "./search";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useListPagination } from "@/hooks/use-list-pagination";

export function AuditView({
  search,
  onSearch,
  accountPicker,
  devicePicker,
}: {
  search: AuditSearch;
  onSearch: (next: AuditSearch) => void;
  accountPicker: PickerSlot;
  devicePicker: PickerSlot;
}) {
  const { pageSize, pageToken } = search;
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canOpenDevices = canPermission(principal, "fleet.read", true);
  const canExport = canPermission(principal, "integrations.manage", true);
  const list = useQuery(auditQueryOptions(lifetime, search));
  const pagination = useListPagination(search, (page) => onSearch({ ...search, ...page }));
  const failure = list.error ? toRpcFailure(list.error) : null;
  const clearFilters = () =>
    onSearch({
      ...search,
      view: DEFAULT_AUDIT_VIEW,
      actorId: "",
      deviceId: "",
      from: "",
      through: "",
      pageToken: "",
    });

  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={list.isFetching}>
      <PageHeader
        title="Audit log"
        description="Review who changed what and why. lindm never records secret values."
        onRefresh={() => void list.refetch()}
        refreshing={list.isFetching}
        actions={
          canExport ? (
            <AuditExport
              search={search}
              accountPicker={accountPicker}
              devicePicker={devicePicker}
              disabled={!list.isSuccess || list.isFetching}
            />
          ) : null
        }
      />
      {failure ? <RpcError failure={failure} /> : null}
      <AuditFilters
        search={search}
        accountPicker={accountPicker}
        devicePicker={devicePicker}
        onChange={(next) => onSearch({ ...search, ...next, pageToken: "" })}
      />
      {list.isPending ? (
        <div role="status" className="grid gap-3 border p-4">
          <span className="text-sm text-muted-foreground">Loading audit log…</span>
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : null}
      {list.isSuccess && list.data.events.length === 0 ? (
        <EmptyState
          title={pageToken ? "No more matching events" : "No matching events"}
          description={
            pageToken
              ? "No more events match these filters and time range."
              : "No audit events match these filters and time range."
          }
          action={
            pageToken ? (
              <Button variant="outline" onClick={pagination.previous}>
                {pagination.previousLabel}
              </Button>
            ) : (
              <Button variant="outline" onClick={clearFilters}>
                Clear filters
              </Button>
            )
          }
        />
      ) : null}
      {list.data && list.data.events.length > 0 ? (
        <Table aria-label="Audit events">
          <TableHeader>
            <TableRow>
              <TableHead className="hidden md:table-cell">When</TableHead>
              <TableHead>Action</TableHead>
              <TableHead className="hidden md:table-cell">Who</TableHead>
              <TableHead className="hidden md:table-cell">Device</TableHead>
              <TableHead className="hidden md:table-cell">Reason</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.events.map((event) => {
              const mode =
                event.details.mode === "view"
                  ? "View only"
                  : event.details.mode === "control"
                    ? "Control"
                    : null;
              const duration = auditDuration(event.details.duration_seconds);
              const who = !event.actorId.trim()
                ? "System"
                : event.actorDisplayName.trim()
                  ? `${event.actorDisplayName}${event.actorId === principal.id ? " (you)" : ""}`
                  : event.actorId === principal.id
                    ? "You"
                    : "Account name unavailable";
              const hostname = event.deviceHostname.trim() || "Unnamed device";
              const device =
                event.targetDeviceId && canOpenDevices ? (
                  <Link
                    to="/devices/$deviceId"
                    params={{ deviceId: event.targetDeviceId }}
                    className="underline underline-offset-4 hover:text-primary"
                  >
                    {hostname}
                  </Link>
                ) : event.targetDeviceId ? (
                  hostname
                ) : null;
              const reason = event.reason.trim();
              return (
                <TableRow key={event.id} className="align-top">
                  <TableCell className="hidden whitespace-nowrap md:table-cell">
                    <Timestamp value={event.occurredAt} />
                  </TableCell>
                  <TableCell className="whitespace-normal break-words md:min-w-56">
                    <div>{auditActionLabel(event.action, event.deviceActionCapability)}</div>
                    {mode || duration ? (
                      <p className="text-xs text-muted-foreground">
                        {mode}
                        {mode && duration ? " · " : null}
                        {duration}
                      </p>
                    ) : null}
                    {/* Below md the row stacks: when, who and device under the action. */}
                    <div className="grid gap-0.5 text-xs text-muted-foreground md:hidden">
                      <Timestamp value={event.occurredAt} />
                      <span>
                        {who}
                        {device ? " · " : null}
                        {device}
                      </span>
                      {reason ? <span className="text-foreground">{reason}</span> : null}
                    </div>
                    <TechnicalDetails
                      items={[
                        { label: "Action code", value: event.action.trim() },
                        {
                          label: "Device action capability",
                          value: event.deviceActionCapability.trim(),
                        },
                        { label: "Resource ID", value: event.resourceId.trim() },
                        { label: "Actor ID", value: event.actorId.trim() },
                        { label: "Event ID", value: event.id },
                        { label: "Device ID", value: event.targetDeviceId ?? "" },
                        ...Object.entries(event.details).map(([label, value]) => ({
                          label,
                          value,
                        })),
                      ]}
                    />
                  </TableCell>
                  <TableCell className="hidden min-w-36 whitespace-normal break-words md:table-cell">
                    {who}
                  </TableCell>
                  <TableCell className="hidden min-w-32 whitespace-normal break-words md:table-cell">
                    {device}
                  </TableCell>
                  <TableCell className="hidden min-w-48 whitespace-normal break-words md:table-cell">
                    {reason}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      ) : null}
      <ListPagination
        label="Audit log pages"
        previousLabel={pagination.previousLabel}
        onPrevious={pageToken ? pagination.previous : undefined}
        onNext={
          list.isSuccess && list.data.nextPageToken
            ? () => pagination.next(list.data.nextPageToken)
            : undefined
        }
        busy={list.isFetching}
        pageSize={pageSize}
        pageSizes={PAGE_SIZES}
        onPageSizeChange={(next) => {
          if (next === 50 || next === 100 || next === 200)
            onSearch({ ...search, pageSize: next, pageToken: "" });
        }}
      />
    </section>
  );
}

function auditDuration(value: string | undefined): string | null {
  const seconds = Number(value);
  if (!value || !Number.isSafeInteger(seconds) || seconds <= 0) return null;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (!minutes) return `${remainder} sec`;
  return remainder ? `${minutes} min ${remainder} sec` : `${minutes} min`;
}
