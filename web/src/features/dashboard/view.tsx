import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowUpRightIcon, InfoIcon, RefreshCwIcon, ServerIcon, Settings2Icon } from "lucide-react";
import type { ReactNode } from "react";
import {
  FleetActionOutcome,
  type FleetRecentAction,
} from "../../../gen/lindm/admin/v1/fleet_summary_pb";
import { DeviceFilterSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { formatTimestamp } from "@/lib/time";
import { fleetSummaryQueryOptions, staleContactUntil } from "./queries";
import { StaleDevices } from "./stale-devices";

const actionLabels: Record<string, string> = {
  "device.escrow-rotate.v1": "Rotate escrow recovery key",
  "device.tpm2-bind.v1": "Bind TPM 2.0 unlock",
  "device.lock-sessions.v1": "Lock sessions and local accounts",
  "device.release-lock.v1": "Undo account lock",
  "device.quarantine.v1": "Quarantine network",
  "device.release-quarantine.v1": "Release quarantine",
  "device.crypto-erase.v1": "Wipe encrypted storage",
  "device.sanitize.v1": "Sanitize offline unencrypted disk",
  "device.restart.v1": "Restart device",
  "device.shutdown.v1": "Shut down device",
  "device.refresh-inventory.v1": "Refresh inventory",
  "device.local-admin-rotate.v1": "Rotate managed local-admin password",
};

// Outcome words come from the server's reading of the device's own status
// report; success is never inferred from a closure alone.
const outcomeWords: Record<FleetActionOutcome, { word: string; tone: StatusTone; rank: number }> = {
  [FleetActionOutcome.FAILED]: { word: "failed", tone: "destructive", rank: 0 },
  [FleetActionOutcome.UNKNOWN]: { word: "unknown", tone: "warning", rank: 1 },
  [FleetActionOutcome.UNSPECIFIED]: { word: "unknown", tone: "warning", rank: 1 },
  [FleetActionOutcome.EXPIRED]: { word: "expired", tone: "warning", rank: 2 },
  [FleetActionOutcome.RUNNING]: { word: "running", tone: "info", rank: 3 },
  [FleetActionOutcome.WAITING]: { word: "waiting", tone: "info", rank: 4 },
  [FleetActionOutcome.CANCELLED]: { word: "cancelled", tone: "neutral", rank: 5 },
  [FleetActionOutcome.SUCCEEDED]: { word: "succeeded", tone: "success", rank: 6 },
};

type ActivityGroup = {
  key: string;
  label: string;
  resource: boolean;
  actions: FleetRecentAction[];
  outcomes: { word: string; tone: StatusTone; rank: number; count: number }[];
};

// One row per action kind: every profile-item change is one kind, each device
// capability is its own kind. Rows with failures sort first, then by severity of
// their worst outcome, then by newest action.
function groupActivity(actions: FleetRecentAction[]): ActivityGroup[] {
  const groups = new Map<string, ActivityGroup>();
  for (const action of actions) {
    const resource = action.kind === "resource";
    const key = resource ? "resource" : `device:${action.capability}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        label: resource
          ? "Profile item changes"
          : (actionLabels[action.capability] ?? "Device action"),
        resource,
        actions: [],
        outcomes: [],
      };
      groups.set(key, group);
    }
    group.actions.push(action);
    const outcome = outcomeWords[action.outcome] ?? outcomeWords[FleetActionOutcome.UNKNOWN];
    const counted = group.outcomes.find((entry) => entry.word === outcome.word);
    if (counted) counted.count += 1;
    else group.outcomes.push({ ...outcome, count: 1 });
  }
  const rows = [...groups.values()];
  for (const row of rows) row.outcomes.sort((a, b) => a.rank - b.rank);
  // Map insertion order is newest-first because the server returns newest first.
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => a.row.outcomes[0].rank - b.row.outcomes[0].rank || a.index - b.index)
    .map(({ row }) => row);
}

function plural(count: bigint | number, one: string, many: string) {
  return `${count.toString()} ${count === 1n || count === 1 ? one : many}`;
}

export function DashboardView() {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canReadFleet = canPermission(principal, "fleet.read");
  const summary = useQuery({ ...fleetSummaryQueryOptions(lifetime), enabled: canReadFleet });
  const failure = summary.error ? toRpcFailure(summary.error) : null;
  // A failed refresh must not present a previous response as current evidence.
  const data = canReadFleet && !failure ? summary.data : undefined;
  const contact = data?.contact;
  const compliance = data?.resourceCompliance;
  const findings = data?.findings;
  const approvals = data?.approvals;
  const patch = data?.patchCompliance;
  const observed = formatTimestamp(data?.observedAt);
  const staleFilter =
    data?.observedAt && contact
      ? toJsonString(
          DeviceFilterSchema,
          create(DeviceFilterSchema, {
            lastSeenUntil: staleContactUntil(data.observedAt, contact.staleAfterSeconds),
          }),
        )
      : undefined;
  const uncovered = findings?.unknownDevices ?? 0n;
  const activity = data ? groupActivity(data.recentActions) : [];

  // Workflow order, not a risk score. Never combine unlike populations.
  const next =
    approvals && approvals.pendingApprovals > 0n
      ? "approvals"
      : uncovered > 0n
        ? "coverage"
        : contact && contact.staleDevices > 0n && staleFilter
          ? "contact"
          : compliance &&
              (compliance.attentionResources > 0n ||
                compliance.staleResources > 0n ||
                compliance.unknownResources > 0n)
            ? "profiles"
            : findings &&
                (findings.partialDevices > 0n ||
                  findings.criticalFindings > 0n ||
                  findings.highFindings > 0n ||
                  findings.mediumFindings > 0n ||
                  findings.lowFindings > 0n ||
                  findings.otherFindings > 0n)
              ? "findings"
              : patch &&
                  (patch.securityPendingDevices > 0n ||
                    patch.rebootRequiredDevices > 0n ||
                    patch.staleDevices > 0n ||
                    patch.unknownDevices > 0n ||
                    patch.failedRunDevices > 0n)
                ? "patch"
                : "devices";

  return (
    <section
      className="grid min-w-0 gap-6"
      aria-busy={summary.isFetching}
      data-review-page="dashboard"
    >
      <PageHeader
        title="Dashboard"
        description="Review work in your authorized scopes."
        actions={
          <Button
            variant="outline"
            disabled={!canReadFleet || summary.isFetching}
            data-review-next-action={failure && !summary.isFetching ? "" : undefined}
            onClick={() => {
              if (!lifetime.signal.aborted) void summary.refetch();
            }}
          >
            <RefreshCwIcon aria-hidden="true" />
            {summary.isFetching ? "Refreshing…" : "Refresh"}
          </Button>
        }
      />

      {!canReadFleet ? (
        <Alert data-review-state="blocked">
          <AlertTitle>You can't view the fleet overview</AlertTitle>
          <AlertDescription>
            Ask an owner for fleet read access. You can still check{" "}
            <Link to="/approvals" className="underline">
              Approvals
            </Link>
            .
          </AlertDescription>
        </Alert>
      ) : failure ? (
        <div data-review-state="blocked">
          <RpcError failure={failure} title="Couldn't load the fleet overview" />
        </div>
      ) : summary.isPending ? (
        <p role="status" data-review-state="blocked" className="text-sm text-muted-foreground">
          Loading the work queue. Wait for the current counts before deciding.
        </p>
      ) : null}

      {data ? (
        <>
          <section aria-labelledby="work-queue-title" className="grid gap-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 id="work-queue-title" className="text-base font-semibold">
                Needs review
              </h2>
              <p className="text-xs text-muted-foreground">
                Fleet snapshot{" "}
                {observed.date ? (
                  <time dateTime={observed.utc}>{observed.local}</time>
                ) : (
                  observed.local
                )}
              </p>
            </div>
            <div className="divide-y border-y" data-testid="needs-review">
              <WorkItem
                title="Approval requests"
                primary={next === "approvals"}
                action={
                  <Link to="/approvals" className={queueLinkClass(next === "approvals")}>
                    Review approvals <ArrowUpRightIcon aria-hidden="true" className="size-4" />
                  </Link>
                }
              >
                {approvals ? (
                  <p>
                    <strong className="font-semibold tabular-nums">
                      {approvals.pendingApprovals.toString()}
                    </strong>{" "}
                    pending requests in your inbox.
                  </p>
                ) : (
                  <Unavailable section="Approval summary" />
                )}
                <div className="flex items-center gap-1">
                  <p className="text-xs text-muted-foreground">
                    Review targets and effects before approving. Opening the inbox changes nothing.
                  </p>
                  <Help label="About approval counts">
                    Requests waiting in your approval inbox. Another admin must approve each one
                    before it runs. Pending, unexpired records are counted separately from the fleet
                    snapshot. A pending request is not a guarantee you can approve it; authority is
                    checked again at approval.
                  </Help>
                </div>
              </WorkItem>
              <WorkItem
                title={
                  !findings
                    ? "Vulnerability coverage"
                    : uncovered > 0n
                      ? `${plural(uncovered, "device has", "devices have")} no vulnerability coverage`
                      : "Every active device has vulnerability coverage"
                }
                primary={next === "coverage"}
                action={
                  <Link to="/advisories" className={queueLinkClass(next === "coverage")}>
                    {uncovered > 0n ? "See why and fix coverage" : "Review advisory sources"}{" "}
                    <ArrowUpRightIcon aria-hidden="true" className="size-4" />
                  </Link>
                }
              >
                {findings ? (
                  <p className="text-xs text-muted-foreground">
                    {uncovered > 0n
                      ? "No advisory source has checked these devices' packages, so their exposure is unknown, not zero. Advisories explains the cause and how to add coverage."
                      : `${plural(findings.partialDevices, "device is", "devices are")} only partly checked.`}
                  </p>
                ) : (
                  <Unavailable section="Advisory coverage" />
                )}
              </WorkItem>
              <WorkItem
                title="Stale contact"
                primary={next === "contact"}
                action={
                  staleFilter ? (
                    <Link
                      to="/devices"
                      search={{ pageSize: 50, pageToken: "", filter: staleFilter }}
                      className={queueLinkClass(next === "contact")}
                    >
                      Review stale devices{" "}
                      <ArrowUpRightIcon aria-hidden="true" className="size-4" />
                    </Link>
                  ) : (
                    <Link to="/devices" className={linkClass}>
                      Browse devices
                    </Link>
                  )
                }
              >
                {contact ? (
                  <>
                    <p>
                      <strong className="font-semibold tabular-nums">
                        {contact.staleDevices.toString()}
                      </strong>{" "}
                      devices last seen over {contact.staleAfterSeconds / 3600} hours ago.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Devices with no recorded check-in: {contact.unknownDevices.toString()}.
                      Excluded from the stale list. Review contact evidence before sending work.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Contact summary" />
                )}
                {data.observedAt && contact ? (
                  <details className="mt-1">
                    <summary className="cursor-pointer text-sm font-medium">
                      Preview stale devices
                    </summary>
                    <div className="mt-3">
                      <StaleDevices
                        observedAt={data.observedAt}
                        staleAfterSeconds={contact.staleAfterSeconds}
                        staleTotal={contact.staleDevices}
                      />
                    </div>
                  </details>
                ) : null}
              </WorkItem>
              <WorkItem
                title="Profile items"
                primary={next === "profiles"}
                action={
                  <Link to="/devices" className={queueLinkClass(next === "profiles")}>
                    Inspect device services{" "}
                    <ArrowUpRightIcon aria-hidden="true" className="size-4" />
                  </Link>
                }
              >
                {compliance ? (
                  <>
                    <p>
                      <strong className="font-semibold tabular-nums">
                        {compliance.attentionResources.toString()}
                      </strong>{" "}
                      items need attention · {compliance.staleResources.toString()} not checked
                      recently · {compliance.unknownResources.toString()} unknown.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Counts assigned items, not devices. Open a device's Services tab for the cause
                      before changing its profile.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Profile item summary" />
                )}
              </WorkItem>
              <WorkItem
                title="Security findings"
                primary={next === "findings"}
                action={
                  <Link to="/advisories" className={queueLinkClass(next === "findings")}>
                    Review advisory evidence{" "}
                    <ArrowUpRightIcon aria-hidden="true" className="size-4" />
                  </Link>
                }
              >
                {findings ? (
                  <>
                    <p>
                      <strong className="font-semibold tabular-nums">
                        {findings.criticalFindings.toString()}
                      </strong>{" "}
                      critical findings · {findings.highFindings.toString()} high findings.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Counts findings on{" "}
                      {plural(findings.evaluatedDevices, "checked device", "checked devices")}.
                      Accepted findings are excluded; zero findings does not mean no exposure.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Advisory summary" />
                )}
              </WorkItem>
              <WorkItem
                title="OS patch follow-up"
                primary={next === "patch"}
                action={
                  <Link to="/devices" className={queueLinkClass(next === "patch")}>
                    Inspect device patch status{" "}
                    <ArrowUpRightIcon aria-hidden="true" className="size-4" />
                  </Link>
                }
              >
                {patch ? (
                  <>
                    <p>
                      {patch.securityPendingDevices.toString()} active devices with security updates
                      pending · {patch.rebootRequiredDevices.toString()} requiring reboot.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {patch.staleDevices.toString()} stale · {patch.unknownDevices.toString()}{" "}
                      unknown · {patch.failedRunDevices.toString()} whose last update run failed.
                      Inspect device-reported status before choosing a maintenance action.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Patch compliance" />
                )}
              </WorkItem>
            </div>
            {next === "devices" ? (
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm text-muted-foreground">
                  Review device evidence for enrollment, missing contact and any unavailable
                  summaries. This queue is not a fleet health assessment.
                </p>
                <Link to="/devices" data-review-next-action="" className={queueLinkClass(true)}>
                  Inspect device evidence <ArrowUpRightIcon aria-hidden="true" className="size-4" />
                </Link>
              </div>
            ) : null}
          </section>

          <section aria-labelledby="recent-activity-title" className="grid gap-3">
            <div>
              <h2 id="recent-activity-title" className="text-base font-semibold">
                Latest recorded activity
              </h2>
              <p className="text-xs text-muted-foreground">
                The {plural(data.recentActions.length, "newest action", "newest actions")} in your
                device scopes, grouped by kind. Outcomes are what devices reported; open a device
                for details.
              </p>
            </div>
            {activity.length ? (
              <ul className="divide-y border-y" data-testid="activity-groups">
                {activity.map((group) => {
                  const latest = group.actions[0];
                  const devices = new Set(group.actions.map((action) => action.deviceId)).size;
                  return (
                    <li
                      key={group.key}
                      data-activity-kind={group.key}
                      className="flex items-start gap-3 py-3"
                    >
                      <span className="flex size-8 shrink-0 items-center justify-center bg-muted text-muted-foreground">
                        {group.resource ? (
                          <Settings2Icon className="size-4" aria-hidden="true" />
                        ) : (
                          <ServerIcon className="size-4" aria-hidden="true" />
                        )}
                      </span>
                      <div className="grid min-w-0 flex-1 gap-1">
                        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                          <span className="break-words text-sm font-medium">
                            {group.label}{" "}
                            <span
                              className="font-normal text-muted-foreground"
                              data-activity-count=""
                            >
                              · {plural(group.actions.length, "action", "actions")}
                            </span>
                          </span>
                          <span className="flex flex-wrap gap-1" data-activity-outcomes="">
                            {group.outcomes.map((outcome) => (
                              <StatusBadge key={outcome.word} status={outcome.tone}>
                                {outcome.count} {outcome.word}
                              </StatusBadge>
                            ))}
                          </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                          <span>
                            {plural(devices, "device", "devices")} · latest{" "}
                            {formatTimestamp(latest.createdAt).local}
                          </span>
                          <Link
                            to="/devices/$deviceId"
                            params={{ deviceId: latest.deviceId }}
                            search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                            className={linkClass}
                          >
                            {devices === 1 ? "Open device" : "Open latest device"}
                          </Link>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <EmptyState
                title="No recorded actions in your device scopes"
                description="This is an action history, not confirmation that devices need no work."
              />
            )}
          </section>
        </>
      ) : null}
    </section>
  );
}

const linkClass =
  "inline-flex min-h-8 items-center gap-1 text-sm font-medium text-foreground underline underline-offset-4 hover:decoration-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

function queueLinkClass(primary: boolean) {
  return primary
    ? buttonVariants({ className: "h-auto min-h-8 whitespace-normal text-left" })
    : linkClass;
}

function WorkItem({
  title,
  primary,
  action,
  children,
}: {
  title: string;
  primary: boolean;
  action: ReactNode;
  children: ReactNode;
}) {
  return (
    <div
      data-review-metric=""
      className={`grid gap-3 px-3 py-4 sm:grid-cols-[minmax(0,1fr)_auto] ${primary ? "border-l-2 border-l-primary bg-accent/40" : ""}`}
    >
      <div className="grid min-w-0 gap-1 text-sm">
        {primary ? <p className="text-xs font-medium text-muted-foreground">Start here</p> : null}
        <h3 className="font-semibold">{title}</h3>
        {children}
      </div>
      <div className="self-start" data-review-next-action={primary ? "" : undefined}>
        {action}
      </div>
    </div>
  );
}

function Help({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger
        aria-label={label}
        className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <InfoIcon className="size-3.5" aria-hidden="true" />
      </TooltipTrigger>
      <TooltipContent className="max-w-sm text-xs leading-relaxed">{children}</TooltipContent>
    </Tooltip>
  );
}

function Unavailable({ section }: { section: string }) {
  return (
    <p data-review-state="blocked" className="text-sm text-muted-foreground">
      {section} unavailable. Review the linked evidence; no zero is assumed.
    </p>
  );
}
