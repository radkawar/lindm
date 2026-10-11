import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
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
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { PAGE_SIZES } from "@/lib/list-search";
import { canPermission } from "@/lib/permissions";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { auditQueryOptions } from "./queries";
import { AuditExport } from "./export";
import { AuditFilters } from "./filters";
import type { AuditSearch } from "./search";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useListPagination } from "@/hooks/use-list-pagination";

const ACTION_LABELS: Record<string, string> = {
  "device_action.escrow_receipt": "Recovery secret storage confirmed",
  "identity.authorization_updated": "Organization access policy changed",
};

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
  const list = useQuery(auditQueryOptions(lifetime, search));
  const pagination = useListPagination(search, (page) => onSearch({ ...search, ...page }));
  const failure = list.error ? toRpcFailure(list.error) : null;
  const now = new Date();

  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={list.isFetching}>
      <PageHeader
        title="Audit log"
        description="Who changed what, and why. Secret values are never recorded."
        actions={
          <div className="flex flex-wrap gap-2">
            <AuditExport
              search={search}
              accountPicker={accountPicker}
              devicePicker={devicePicker}
              disabled={!list.isSuccess || list.isFetching}
            />
            <Button
              variant="outline"
              onClick={() => void list.refetch()}
              disabled={list.isFetching}
            >
              Refresh
            </Button>
          </div>
        }
      />
      {failure ? <RpcError failure={failure} /> : null}
      <AuditFilters
        search={search}
        accountPicker={accountPicker}
        devicePicker={devicePicker}
        onChange={(next) => onSearch({ ...search, ...next, pageToken: "" })}
      />
      <div className="flex flex-wrap items-center gap-2 border-y py-3 text-sm">
        <Label htmlFor="audit-page-size">Page size</Label>
        <SelectField
          id="audit-page-size"
          className="h-9"
          value={pageSize}
          onValueChange={(value) => {
            const next = Number(value);
            if (next === 50 || next === 100 || next === 200) {
              onSearch({ ...search, pageSize: next, pageToken: "" });
            }
          }}
          options={PAGE_SIZES.map((size) => ({ value: size, label: size }))}
        />
      </div>
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
          title="No matching events"
          description={
            pageToken
              ? "No more events match the chosen scope and time range. Return to the previous page or change the filters."
              : "No audit events match the chosen scope and time range. Choose another range or clear the filters."
          }
        />
      ) : null}
      {list.data && list.data.events.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>When</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Who</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead>Device</TableHead>
              <TableHead>
                <span className="sr-only">Details</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.events.map((event) => {
              const occurred = formatTimestamp(event.occurredAt);
              const mode =
                event.details.mode === "view"
                  ? "View only"
                  : event.details.mode === "control"
                    ? "Control"
                    : null;
              const duration = auditDuration(event.details.duration_seconds);
              return (
                <TableRow key={event.id}>
                  <TableCell>
                    {occurred.date ? (
                      <time dateTime={occurred.utc}>
                        {occurred.local} ({freshnessLabel(occurred.date, now)})
                      </time>
                    ) : (
                      "Not recorded"
                    )}
                  </TableCell>
                  <TableCell>
                    <div>
                      {event.action.trim()
                        ? (ACTION_LABELS[event.action.trim()] ??
                          event.action
                            .trim()
                            .replace(/[._]+/g, " ")
                            .replace(/^./, (first) => first.toUpperCase()))
                        : "Not recorded"}
                    </div>
                    {mode || duration ? (
                      <p className="text-xs text-muted-foreground">
                        {mode}
                        {mode && duration ? " · " : null}
                        {duration}
                      </p>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    {!event.actorId.trim()
                      ? "System"
                      : event.actorDisplayName.trim()
                        ? `${event.actorDisplayName}${event.actorId === principal.id ? " (you)" : ""}`
                        : event.actorId === principal.id
                          ? "You"
                          : "Account name unavailable"}
                  </TableCell>
                  <TableCell className="min-w-48 max-w-md whitespace-normal break-words">
                    {event.reason.trim() || "Not recorded"}
                  </TableCell>
                  <TableCell>
                    {event.targetDeviceId && canOpenDevices ? (
                      <Link
                        to="/devices/$deviceId"
                        params={{ deviceId: event.targetDeviceId }}
                        className="underline underline-offset-4 hover:text-primary"
                      >
                        {event.deviceHostname.trim() || "Unnamed device"}
                      </Link>
                    ) : event.targetDeviceId ? (
                      event.deviceHostname.trim() || "Unnamed device"
                    ) : (
                      "Not recorded"
                    )}
                  </TableCell>
                  <TableCell>
                    <TechnicalDetails
                      items={[
                        { label: "Action code", value: event.action.trim() },
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
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" disabled={pageToken === ""} onClick={pagination.previous}>
          {pagination.previousLabel}
        </Button>
        <Button
          variant="outline"
          disabled={!list.isSuccess || !list.data.nextPageToken || list.isFetching}
          onClick={() => pagination.next(list.data?.nextPageToken ?? "")}
        >
          Next page
        </Button>
      </div>
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
