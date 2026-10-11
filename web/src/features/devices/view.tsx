import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  MoreHorizontal,
  RefreshCw,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { DeviceCompliance, type Device } from "../../../gen/lindm/admin/v1/admin_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { StatusBadge } from "@/components/ui/status-badge";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SelectField } from "@/components/ui/select-field";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
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
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { PAGE_SIZES } from "@/lib/list-search";
import { canPermission } from "@/lib/permissions";
import { AttributeDefinitions } from "./definitions";
import { DeviceExport, DeviceFilters } from "./filters";
import { DeviceLifecycleBadge } from "./lifecycle-badge";
import { ObservedTime } from "./observations";
import { devicesQueryOptions } from "./queries";
import type { DeviceSearch } from "./search";

const columns = [
  { id: "hostname", label: "Device", sortable: true },
  { id: "state", label: "State", sortable: false },
  { id: "compliance", label: "Compliance", sortable: false },
  { id: "contact", label: "Last contact", sortable: true },
  { id: "os", label: "Operating system", sortable: true },
  { id: "host", label: "Host received", sortable: false },
  { id: "inventory", label: "Inventory", sortable: false },
  { id: "metadata", label: "Owner / labels / attributes", sortable: false },
  { id: "id", label: "Device ID", sortable: true },
] as const;
type ColumnId = (typeof columns)[number]["id"];
type Sort = { column: ColumnId; descending: boolean };

function compareDevices(left: Device, right: Device, column: ColumnId) {
  if (column === "contact") {
    const a = left.lastSeenAt;
    const b = right.lastSeenAt;
    if (!a || !b) return a ? 1 : b ? -1 : 0;
    if (a.seconds !== b.seconds) return a.seconds < b.seconds ? -1 : 1;
    return a.nanos - b.nanos;
  }
  const a =
    column === "hostname"
      ? left.hostname
      : column === "os"
        ? `${left.osId} ${left.osVersion} ${left.architecture}`
        : left.id;
  const b =
    column === "hostname"
      ? right.hostname
      : column === "os"
        ? `${right.osId} ${right.osVersion} ${right.architecture}`
        : right.id;
  return a.localeCompare(b, undefined, { numeric: true });
}

const complianceLabels: Record<DeviceCompliance, string> = {
  [DeviceCompliance.UNSPECIFIED]: "Unknown",
  [DeviceCompliance.UNASSIGNED]: "Unassigned",
  [DeviceCompliance.COMPLIANT]: "Compliant",
  [DeviceCompliance.DRIFT_REMEDIATED]: "Drift remediated",
  [DeviceCompliance.STALE]: "Stale",
  [DeviceCompliance.UNKNOWN]: "Unknown",
  [DeviceCompliance.ATTENTION]: "Attention",
};

function DeviceCell({ device, column }: { device: Device; column: ColumnId }) {
  switch (column) {
    case "hostname":
      return (
        <Link
          to="/devices/$deviceId"
          params={{ deviceId: device.id }}
          search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
          className="font-medium text-foreground underline-offset-4 hover:text-primary hover:underline focus-visible:underline"
        >
          {device.hostname.trim() || "Hostname not reported"}
        </Link>
      );
    case "state":
      return <DeviceLifecycleBadge state={device.lifecycleState} />;
    case "compliance":
      return (
        <Tooltip>
          <TooltipTrigger
            render={
              <StatusBadge
                dot
                tabIndex={0}
                status={
                  device.compliance === DeviceCompliance.ATTENTION
                    ? "destructive"
                    : device.compliance === DeviceCompliance.STALE
                      ? "warning"
                      : device.compliance === DeviceCompliance.COMPLIANT ||
                          device.compliance === DeviceCompliance.DRIFT_REMEDIATED
                        ? "success"
                        : "neutral"
                }
              />
            }
          >
            {complianceLabels[device.compliance] ?? "Unknown"}
          </TooltipTrigger>
          <TooltipContent className="block space-y-2">
            <p>Worst status across the services assigned to this device.</p>
            <p>
              {device.lastVerifiedAt ? (
                <>
                  Last fully checked: <ObservedTime value={device.lastVerifiedAt} server />.
                </>
              ) : (
                "Not fully checked yet."
              )}
            </p>
          </TooltipContent>
        </Tooltip>
      );
    case "contact":
      return <ObservedTime value={device.lastSeenAt} server relative />;
    case "os":
      return (
        <span>
          {[device.osId, device.osVersion].filter((part) => part.trim() !== "").join(" ") ||
            "Not reported"}
          <span className="text-muted-foreground"> · {device.architecture || "Unknown arch"}</span>
        </span>
      );
    case "host":
      return <ObservedTime value={device.hostReceivedAt} server />;
    case "inventory":
      return device.publishedSnapshotSequence === 0n ? (
        "Not published"
      ) : (
        <>
          #{device.publishedSnapshotSequence.toString()} ·{" "}
          <ObservedTime value={device.snapshotReceivedAt} server relative />
        </>
      );
    case "metadata":
      return (
        <>
          <p>{device.metadata?.owner.value ?? "Unassigned"}</p>
          <p className="text-muted-foreground">
            {device.metadata?.labels.join(", ") || "No labels"}
          </p>
          {Object.entries(device.metadata?.attributes ?? {}).map(([key, value]) => (
            <p key={key}>
              {key}: {value.value.value?.toString() ?? "Not set"}
            </p>
          ))}
        </>
      );
    case "id":
      return <span className="font-mono text-xs">{device.id}</span>;
  }
}

export function DevicesView({
  search,
  onSearch,
  renderRevoke,
}: {
  search: DeviceSearch;
  onSearch: (next: DeviceSearch, replace?: boolean) => void;
  renderRevoke?: (device: Device) => ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canRead = canPermission(principal, "fleet.read");
  const canRevoke = canPermission(principal, "device.revoke");
  const list = useQuery({ ...devicesQueryOptions(lifetime, search), enabled: canRead });
  const pagination = useListPagination(search, (next) => onSearch({ ...search, ...next }));
  const [sort, setSort] = useState<Sort | null>(null);
  const [compact, setCompact] = useState(true);
  const [visible, setVisible] = useState<ColumnId[]>([
    "hostname",
    "state",
    "compliance",
    "contact",
    "os",
    "inventory",
  ]);
  const failure = list.error ? toRpcFailure(list.error) : null;
  const data = failure ? undefined : list.data;
  const rows = useMemo(
    () =>
      sort && data
        ? [...data.devices].sort(
            (a, b) => compareDevices(a, b, sort.column) * (sort.descending ? -1 : 1),
          )
        : (data?.devices ?? []),
    [data, sort],
  );
  const visibleColumns = columns.filter((column) => visible.includes(column.id));
  const pageToken = data?.pageToken;
  const freshResponse = list.isFetchedAfterMount && !list.isFetching;
  useEffect(() => {
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

  if (!canRead) return <p role="alert">Fleet read permission is required to view inventory.</p>;
  return (
    <section className="flex min-w-0 flex-col gap-5" aria-busy={list.isFetching}>
      <PageHeader
        title="Devices"
        description="Manage enrolled devices and their reported inventory."
        actions={
          <Button variant="outline" onClick={() => void list.refetch()} disabled={list.isFetching}>
            <RefreshCw aria-hidden="true" /> Refresh
          </Button>
        }
      />
      <DeviceFilters search={search} onSearch={onSearch} />
      {failure ? <RpcError failure={failure} title="Device list unavailable" /> : null}
      <div className="min-w-0 border bg-card">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
          <div className="text-sm">
            <span className="font-medium">
              {data ? `${data.devices.length} devices on this page` : "Device inventory"}
            </span>
            <p className="text-xs text-muted-foreground">
              {sort ? "Sorted within this page" : "Default order"}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {sort ? (
              <Button size="sm" variant="ghost" onClick={() => setSort(null)}>
                Reset sort
              </Button>
            ) : null}
            <details className="relative">
              <summary className="cursor-pointer border border-input px-3 py-1.5 text-sm focus-visible:outline focus-visible:outline-ring">
                Columns
              </summary>
              <fieldset className="absolute right-0 z-20 mt-2 grid min-w-64 gap-3 border bg-popover p-4 text-sm text-popover-foreground shadow-md">
                <legend className="sr-only">Visible device columns</legend>
                {columns.map((column) => (
                  <label key={column.id} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      className="accent-primary"
                      checked={visible.includes(column.id)}
                      disabled={column.id === "hostname"}
                      onChange={(event) => {
                        setVisible((current) =>
                          event.target.checked
                            ? [...current, column.id]
                            : current.filter((id) => id !== column.id),
                        );
                        if (!event.target.checked && sort?.column === column.id) setSort(null);
                      }}
                    />
                    {column.label}
                  </label>
                ))}
              </fieldset>
            </details>
            <Button
              size="sm"
              variant="outline"
              aria-pressed={compact}
              onClick={() => setCompact(!compact)}
            >
              Compact rows
            </Button>
          </div>
        </div>
        {list.isPending ? (
          <p role="status" className="p-8 text-sm text-muted-foreground">
            Loading devices…
          </p>
        ) : null}
        {data?.devices.length === 0 ? (
          <EmptyState
            title="No devices match this page"
            description="Adjust your inventory filters or start a new search for the latest enrollments."
            action={
              <Button variant="outline" onClick={() => onSearch({ ...search, pageToken: "" })}>
                Start new search
              </Button>
            }
          />
        ) : null}
        {rows.length > 0 ? (
          <Table className={compact ? "[&_td]:h-12 [&_td]:py-2" : "[&_td]:py-4"}>
            <caption className="sr-only">
              Enrolled devices. Sorting applies to the current page only.
            </caption>
            <TableHeader className="bg-muted/40">
              <TableRow>
                {visibleColumns.map((column) => (
                  <TableHead
                    key={column.id}
                    className="px-4"
                    aria-sort={
                      sort?.column === column.id
                        ? sort.descending
                          ? "descending"
                          : "ascending"
                        : undefined
                    }
                  >
                    {column.sortable ? (
                      <button
                        type="button"
                        className="flex items-center gap-2 py-2 text-xs font-medium focus-visible:outline focus-visible:outline-ring"
                        aria-label={`Sort this page by ${column.label}`}
                        onClick={() =>
                          setSort({
                            column: column.id,
                            descending: sort?.column === column.id && !sort.descending,
                          })
                        }
                      >
                        {column.label}
                        {sort?.column === column.id ? (
                          sort.descending ? (
                            <ArrowDown className="size-3.5" aria-hidden="true" />
                          ) : (
                            <ArrowUp className="size-3.5" aria-hidden="true" />
                          )
                        ) : (
                          <ArrowUpDown
                            className="size-3.5 text-muted-foreground"
                            aria-hidden="true"
                          />
                        )}
                      </button>
                    ) : (
                      <span className="text-xs">{column.label}</span>
                    )}
                  </TableHead>
                ))}
                {renderRevoke && canRevoke ? (
                  <TableHead className="px-4 text-xs">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                ) : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((device) => (
                <TableRow key={device.id}>
                  {visibleColumns.map((column) => (
                    <TableCell key={column.id} className="max-w-80 truncate px-4">
                      <DeviceCell device={device} column={column.id} />
                    </TableCell>
                  ))}
                  {renderRevoke && canRevoke ? (
                    <TableCell className="w-12 px-4">
                      <DeviceRevokeDialog device={device}>
                        {renderRevoke(device)}
                      </DeviceRevokeDialog>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t px-4 py-3 text-sm">
          <div className="flex items-center gap-2">
            <Label htmlFor="device-page-size">Rows per page</Label>
            <SelectField
              id="device-page-size"
              className="w-20"
              value={String(search.pageSize)}
              onValueChange={(value) => {
                const next = Number(value);
                if (next === 50 || next === 100 || next === 200)
                  onSearch({ ...search, pageSize: next, pageToken: "" });
              }}
              options={PAGE_SIZES.map((size) => ({ value: String(size), label: size }))}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="ghost"
              disabled={list.isFetching}
              onClick={() => {
                if (search.pageToken) onSearch({ ...search, pageToken: "" });
                else void list.refetch();
              }}
            >
              New search / latest devices
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={pagination.previousLabel !== "Previous page" || list.isFetching}
              onClick={pagination.previous}
            >
              <ChevronLeft aria-hidden="true" /> Previous page
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!data?.nextPageToken || list.isFetching || search.pageToken === ""}
              onClick={() => pagination.next(data?.nextPageToken ?? "")}
            >
              Next page <ChevronRight aria-hidden="true" />
            </Button>
          </div>
        </div>
      </div>
      {data ? (
        <p className="text-xs text-muted-foreground">
          This search expires <ObservedTime value={data.cursorExpiresAt} />. Start a new search to
          see newly enrolled devices.
        </p>
      ) : null}
      <details className="border bg-card">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium">Export devices</summary>
        <DeviceExport key={`${search.filter ?? ""}:${search.pageSize}`} search={search} />
      </details>
      <details className="border bg-card">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium">
          Custom attributes
        </summary>
        <AttributeDefinitions />
      </details>
    </section>
  );
}

function DeviceRevokeDialog({ device, children }: { device: Device; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [visited, setVisited] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) setVisited(true);
      }}
    >
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              ref={triggerRef}
              size="icon-sm"
              variant="ghost"
              aria-label={`Actions for ${device.hostname || device.id}`}
            />
          }
        >
          <MoreHorizontal aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-44">
          <DropdownMenuItem
            variant="destructive"
            onClick={() => {
              setVisited(true);
              setOpen(true);
            }}
          >
            Revoke device…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {visited ? (
        <DialogContent keepMounted finalFocus={triggerRef} className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Revoke {device.hostname || "device"}</DialogTitle>
            <DialogDescription>
              Another admin must approve before this device is removed from lindm.
            </DialogDescription>
          </DialogHeader>
          {children}
        </DialogContent>
      ) : null}
    </Dialog>
  );
}
