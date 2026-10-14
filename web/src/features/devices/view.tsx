// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Info,
  MoreHorizontal,
  RefreshCw,
} from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  DeviceRootEncryption,
  DeviceState,
  type Device,
} from "../../../gen/lindm/admin/v1/admin_pb";
import { DeviceCompliance } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { Button, buttonVariants } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
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
import { DeviceExport, DeviceFilters } from "./filters";
import { DeviceLifecycleBadge } from "./lifecycle-badge";
import { deviceOsLabel } from "./os";
import { ObservedTime } from "./observations";
import { devicesQueryOptions } from "./queries";
import type { DeviceSearch, DeviceSortColumn } from "./search";

const columns = [
  { id: "hostname", label: "Device", sortable: true },
  { id: "state", label: "State", sortable: false },
  { id: "compliance", label: "Compliance", sortable: false },
  { id: "encryption", label: "Encryption", sortable: false },
  { id: "updates", label: "Updates", sortable: false },
  { id: "findings", label: "Findings", sortable: false },
  { id: "contact", label: "Last contact", sortable: true },
  { id: "os", label: "Operating system", sortable: true },
  { id: "host", label: "Device facts received", sortable: false },
  { id: "inventory", label: "Last inventory", sortable: false },
  { id: "metadata", label: "Owner / labels / attributes", sortable: false },
  { id: "id", label: "Device ID", sortable: false },
] as const;
type ColumnId = (typeof columns)[number]["id"];

const complianceLabels: Record<DeviceCompliance, string> = {
  [DeviceCompliance.UNSPECIFIED]: "Unknown",
  [DeviceCompliance.UNASSIGNED]: "No profile",
  [DeviceCompliance.COMPLIANT]: "Compliant",
  [DeviceCompliance.DRIFT_REMEDIATED]: "Drift remediated",
  [DeviceCompliance.STALE]: "Stale",
  [DeviceCompliance.UNKNOWN]: "Unknown",
  [DeviceCompliance.ATTENTION]: "Attention",
};

const unknownEncryption: [string, StatusTone, string] = [
  "Unknown",
  "neutral",
  "No inventory report has identified how the root filesystem is stored yet.",
];
const encryptionLabels: Record<DeviceRootEncryption, [string, StatusTone, string]> = {
  [DeviceRootEncryption.UNSPECIFIED]: unknownEncryption,
  [DeviceRootEncryption.UNKNOWN]: unknownEncryption,
  [DeviceRootEncryption.ENCRYPTED]: [
    "Encrypted",
    "success",
    "The root filesystem is on an encrypted volume.",
  ],
  [DeviceRootEncryption.NOT_ENCRYPTED]: [
    "Not encrypted",
    "warning",
    "No disk encryption was found under the root filesystem.",
  ],
};

// Posture cells: a focusable state whose tooltip carries the evidence. Neutral
// states stay plain text so attention badges stand out in a long table.
function PostureBadge({
  tone,
  label,
  children,
}: {
  tone: StatusTone;
  label: string;
  children: ReactNode;
}) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          tone === "neutral" ? (
            <span tabIndex={0} className="text-muted-foreground" />
          ) : (
            <StatusBadge dot tabIndex={0} status={tone} />
          )
        }
      >
        {label}
      </TooltipTrigger>
      <TooltipContent className="block max-w-72 space-y-2">{children}</TooltipContent>
    </Tooltip>
  );
}

function plural(count: number, noun: string) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function DeviceCell({
  device,
  column,
  findings = false,
}: {
  device: Device;
  column: ColumnId;
  findings?: boolean;
}) {
  switch (column) {
    case "hostname":
      return (
        <span className="grid">
          <Link
            to="/devices/$deviceId"
            params={{ deviceId: device.id }}
            search={findings ? { tab: "findings" } : {}}
            className="font-medium text-foreground underline-offset-4 hover:text-primary hover:underline focus-visible:underline"
          >
            {device.hostname.trim() ||
              (device.lifecycleState === DeviceState.PENDING
                ? "Device awaiting approval"
                : "Unnamed device")}
          </Link>
          {!device.hostname.trim() && device.enrolledAt ? (
            <span className="text-xs text-muted-foreground">
              Requested <ObservedTime value={device.enrolledAt} server relative />
            </span>
          ) : null}
        </span>
      );
    case "state":
      return <DeviceLifecycleBadge state={device.lifecycleState} />;
    case "compliance": {
      const tone: StatusTone =
        device.compliance === DeviceCompliance.ATTENTION
          ? "destructive"
          : device.compliance === DeviceCompliance.STALE
            ? "warning"
            : device.compliance === DeviceCompliance.COMPLIANT ||
                device.compliance === DeviceCompliance.DRIFT_REMEDIATED
              ? "success"
              : "neutral";
      return (
        <PostureBadge tone={tone} label={complianceLabels[device.compliance] ?? "Unknown"}>
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
        </PostureBadge>
      );
    }
    case "encryption": {
      const [label, tone, detail] = encryptionLabels[device.rootEncryption] ?? unknownEncryption;
      return (
        <PostureBadge tone={tone} label={label}>
          <p>{detail}</p>
          <p>From the latest inventory report.</p>
        </PostureBadge>
      );
    }
    case "updates": {
      const updates = device.updates;
      if (!updates)
        return (
          <PostureBadge tone="neutral" label="Unknown">
            <p>No update status reported, or the update service is unavailable.</p>
          </PostureBadge>
        );
      const tone: StatusTone =
        updates.stale || updates.pendingSecurityUpdates > 0 || updates.rebootRequired
          ? "warning"
          : updates.pendingUpdates > 0
            ? "neutral"
            : "success";
      const label = updates.pendingUpdates > 0 ? `${updates.pendingUpdates} pending` : "Up to date";
      const security = plural(updates.pendingSecurityUpdates, "security update");
      return (
        <PostureBadge tone={tone} label={label}>
          <p>
            {security} pending{updates.rebootRequired ? " · Restart required" : ""}
          </p>
          <p>
            Reported <ObservedTime value={updates.receivedAt} server />
            {updates.stale ? ". This report is old; counts may be out of date." : "."}
          </p>
        </PostureBadge>
      );
    }
    case "findings": {
      const findings = device.findings;
      if (!findings)
        return (
          <PostureBadge tone="neutral" label="Not checked">
            <p>No current advisory check covers this device. Advisories shows why.</p>
          </PostureBadge>
        );
      const tone: StatusTone = findings.partial
        ? "neutral"
        : findings.critical > 0
          ? "destructive"
          : findings.high > 0
            ? "warning"
            : "success";
      // The cell names the worst severity only; the tooltip carries every count.
      const label =
        findings.critical > 0
          ? `${findings.critical} critical`
          : findings.high > 0
            ? `${findings.high} high`
            : "No critical or high";
      const counts = `${findings.critical} critical, ${findings.high} high`;
      const rest = `${findings.medium} medium, ${findings.low} low, ${findings.other} unrated`;
      return (
        <PostureBadge tone={tone} label={findings.partial ? `${label} · partial` : label}>
          <p>
            Open findings: {counts}, {rest}. This count excludes accepted risks.
          </p>
          {findings.partial ? (
            <p>
              Partial check: advisory sources matched only packages from the distribution archive.
            </p>
          ) : null}
        </PostureBadge>
      );
    }
    case "contact":
      return <ObservedTime value={device.lastSeenAt} server relative />;
    case "os": {
      const os = deviceOsLabel(device);
      return os ? (
        <span>
          {os}
          {device.architecture ? (
            <span className="text-muted-foreground"> · {device.architecture}</span>
          ) : null}
        </span>
      ) : (
        <span className="text-muted-foreground">Not reported</span>
      );
    }
    case "host":
      return <ObservedTime value={device.hostReceivedAt} server />;
    case "inventory":
      return device.publishedSnapshotSequence === 0n ? (
        "Not published"
      ) : (
        <ObservedTime value={device.snapshotReceivedAt} server relative />
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
      return <TechnicalDetails items={[{ label: "Device ID", value: device.id }]} />;
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
  // Server-side order across every page; kept in the URL.
  const sort: { column: DeviceSortColumn; descending: boolean } | null = search.sort
    ? { column: search.sort, descending: search.order === "desc" }
    : null;
  const setSort = (next: { column: DeviceSortColumn; descending: boolean } | null) =>
    onSearch({
      ...search,
      sort: next?.column,
      order: next ? (next.descending ? "desc" : "asc") : undefined,
      pageToken: "",
    });
  const [compact, setCompact] = useState(true);
  const [visible, setVisible] = useState<ColumnId[]>([
    "hostname",
    "state",
    "compliance",
    "encryption",
    "updates",
    "findings",
    "contact",
    "os",
    "inventory",
  ]);
  const failure = list.error ? toRpcFailure(list.error) : null;
  const data = failure ? undefined : list.data;
  const rows = data?.devices ?? [];
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

  if (!canRead) return <p role="alert">Ask an owner for fleet read access to view inventory.</p>;
  return (
    <section className="flex min-w-0 flex-col gap-5" aria-busy={list.isFetching}>
      <PageHeader
        title="Devices"
        description="Find a device by hostname, operating system or label. Open the device to act."
        actions={
          <Button variant="outline" onClick={() => void list.refetch()} disabled={list.isFetching}>
            <RefreshCw aria-hidden="true" /> Refresh
          </Button>
        }
      />
      {search.advisoryId ? (
        <div className="grid gap-2 border-l-4 border-warning bg-muted/30 p-4 text-sm">
          <h2 className="font-semibold">Affected devices: {search.advisoryId}</h2>
          <p>
            {search.advisorySeverity} severity. These devices have current findings without an
            active risk acceptance. Open a device to review its packages and update options.
          </p>
          <p className="text-muted-foreground">
            Devices with unknown exposure are not included. An empty list does not prove the fleet
            is clear.
          </p>
          <Link to="/advisories" hash="advisory-findings" className="underline underline-offset-4">
            Back to advisories and coverage
          </Link>
        </div>
      ) : null}
      <DeviceFilters search={search} onSearch={onSearch} />
      {failure ? (
        <RpcError failure={failure} title="Device list unavailable">
          {failure.reason === "page_expired" ? (
            <Button
              variant="outline"
              className="mt-2 w-fit"
              onClick={() => onSearch({ ...search, pageToken: "" })}
            >
              Start a new search
            </Button>
          ) : null}
        </RpcError>
      ) : null}
      <div className="min-w-0 border bg-card">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
          <div className="text-sm">
            <span className="font-medium">
              {!data
                ? "Device inventory"
                : data.nextPageToken || pagination.previousLabel === "Previous page"
                  ? `${data.devices.length} devices on this page`
                  : plural(data.devices.length, "device")}
            </span>
            {sort ? (
              <p className="text-xs text-muted-foreground">
                Sorted by {columns.find((column) => column.id === sort.column)?.label.toLowerCase()}
                , {sort.descending ? "descending" : "ascending"}, across all pages
              </p>
            ) : null}
          </div>
          <div className="hidden flex-wrap items-center gap-2 sm:flex">
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
            title={
              search.advisoryId
                ? "No current affected devices matched this advisory"
                : search.filter
                  ? "No devices matched these filters"
                  : "No devices enrolled yet"
            }
            description={
              search.advisoryId
                ? "Accepted risks and devices with unknown exposure are not included. Review advisory coverage, or clear additional device filters."
                : search.filter
                  ? "Clear the filters, or check the hostname, operating system and labels you entered."
                  : "Enrolled and pending devices appear here. Create an enrollment token to add one."
            }
            action={
              search.advisoryId ? (
                <Link to="/advisories" className={buttonVariants({ variant: "outline" })}>
                  Review advisory coverage
                </Link>
              ) : search.filter ? (
                <Button
                  variant="outline"
                  onClick={() => onSearch({ ...search, filter: "", pageToken: "" })}
                >
                  Clear filters
                </Button>
              ) : (
                <Link to="/enrollment" className={buttonVariants({ variant: "outline" })}>
                  Enroll a device
                </Link>
              )
            }
          />
        ) : null}
        {rows.length > 0 ? (
          // Narrow screens read one device per row in decision order; the table needs width.
          <ul className="divide-y sm:hidden" aria-label="Devices">
            {rows.map((device) => (
              <li key={device.id} className="grid gap-2 px-4 py-3 text-sm">
                <div className="flex items-start justify-between gap-2">
                  <span className="min-w-0 [overflow-wrap:anywhere]">
                    <DeviceCell device={device} column="hostname" findings={!!search.advisoryId} />
                  </span>
                  {renderRevoke && canRevoke ? (
                    <DeviceRevokeDialog device={device}>{renderRevoke(device)}</DeviceRevokeDialog>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <DeviceCell device={device} column="state" />
                  {(["compliance", "encryption", "findings"] as const).map((column) => (
                    <span key={column} className="inline-flex items-center gap-1">
                      <span className="text-xs text-muted-foreground">
                        {columns.find((item) => item.id === column)?.label}
                      </span>
                      <DeviceCell device={device} column={column} />
                    </span>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">
                  <DeviceCell device={device} column="os" /> · Last contact{" "}
                  <DeviceCell device={device} column="contact" />
                </p>
              </li>
            ))}
          </ul>
        ) : null}
        {rows.length > 0 ? (
          <div className="hidden sm:block">
            <Table className={compact ? "[&_td]:h-12 [&_td]:py-2" : "[&_td]:py-4"}>
              <caption className="sr-only">Enrolled devices.</caption>
              <TableHeader className="bg-muted/40">
                <TableRow>
                  {visibleColumns.map((column) => (
                    <TableHead
                      key={column.id}
                      className="whitespace-normal px-3"
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
                          className="flex items-center gap-2 py-2 text-left text-xs font-medium focus-visible:outline focus-visible:outline-ring"
                          aria-label={`Sort all devices by ${column.label}`}
                          onClick={() =>
                            setSort({
                              column: column.id as DeviceSortColumn,
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
                    <TableHead className="px-3 text-xs">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  ) : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((device) => (
                  <TableRow key={device.id}>
                    {visibleColumns.map((column) => (
                      <TableCell
                        key={column.id}
                        // Hostnames wrap only when genuinely long; status words never break.
                        className={
                          column.id === "hostname" || column.id === "metadata"
                            ? "min-w-36 max-w-56 whitespace-normal px-3 [overflow-wrap:anywhere]"
                            : column.id === "os" ||
                                column.id === "inventory" ||
                                column.id === "contact"
                              ? "whitespace-normal px-3"
                              : "px-3"
                        }
                      >
                        <DeviceCell
                          device={device}
                          column={column.id}
                          findings={!!search.advisoryId}
                        />
                      </TableCell>
                    ))}
                    {renderRevoke && canRevoke ? (
                      <TableCell className="w-12 px-3">
                        <DeviceRevokeDialog device={device}>
                          {renderRevoke(device)}
                        </DeviceRevokeDialog>
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
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
              Show latest devices
            </Button>
            {data ? (
              <Tooltip>
                <TooltipTrigger
                  render={
                    <Button size="icon-sm" variant="ghost" aria-label="About paging this search" />
                  }
                >
                  <Info aria-hidden="true" />
                </TooltipTrigger>
                <TooltipContent className="block max-w-72">
                  {"You can page through this search until "}
                  <ObservedTime value={data.cursorExpiresAt} />
                  {" at the latest. Show latest devices to include newly enrolled ones."}
                </TooltipContent>
              </Tooltip>
            ) : null}
            {data?.nextPageToken || pagination.previousLabel === "Previous page" ? (
              <>
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
              </>
            ) : null}
          </div>
        </div>
      </div>
      {!search.advisoryId ? (
        <details className="border bg-card">
          <summary className="cursor-pointer px-4 py-3 text-sm font-medium">Export devices</summary>
          <DeviceExport key={`${search.filter ?? ""}:${search.pageSize}`} search={search} />
        </details>
      ) : null}
    </section>
  );
}

export function DeviceRevocationImpact({ device }: { device: Device }) {
  return (
    <dl className="grid gap-3 text-sm">
      <div data-review-impact="targets">
        <dt className="font-medium">Selected device</dt>
        <dd className="break-words">{device.hostname.trim() || "Unnamed device"}</dd>
      </div>
      <div data-review-impact="count">
        <dt className="font-medium">Scope</dt>
        <dd>1 device</dd>
      </div>
      <div data-review-impact="effects">
        <dt className="font-medium">Access and data</dt>
        <dd>
          Revokes this device&apos;s access to lindm. This is not a disk wipe or an account lock.
        </dd>
      </div>
      <div data-review-impact="reversibility">
        <dt className="font-medium">Recovery</dt>
        <dd>
          Revocation stops existing device credentials. Use recovery enrollment to restore
          management.
        </dd>
      </div>
      <div data-review-impact="approval">
        <dt className="font-medium">Approval required</dt>
        <dd>
          This requests approval, not immediate revocation. Another administrator must approve
          within one hour. Finish the revocation in Approvals after approval.
        </dd>
      </div>
    </dl>
  );
}

function DeviceRevokeDialog({ device, children }: { device: Device; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              ref={triggerRef}
              size="icon-sm"
              variant="ghost"
              aria-label={`Actions for ${device.hostname.trim() || "Unnamed device"}`}
            />
          }
        >
          <MoreHorizontal aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-44">
          <DropdownMenuItem
            variant="destructive"
            aria-haspopup="dialog"
            onClick={() => setOpen(true)}
          >
            Revoke device…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <DialogContent
        data-review-destructive="revoke-device"
        finalFocus={triggerRef}
        className="max-h-[90svh] overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>Revoke {device.hostname.trim() || "Unnamed device"}</DialogTitle>
          <DialogDescription>
            Review the access change before requesting approval.
          </DialogDescription>
        </DialogHeader>
        <DeviceRevocationImpact device={device} />
        {children}
      </DialogContent>
    </Dialog>
  );
}
