import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ActivityIcon,
  ArrowUpRightIcon,
  InfoIcon,
  RefreshCwIcon,
  ServerIcon,
  Settings2Icon,
} from "lucide-react";
import type { ReactNode } from "react";
import type { FleetRecentAction } from "../../../gen/lindm/admin/v1/fleet_summary_pb";
import { DeviceFilterSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
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

const osNames: Record<string, string> = {
  almalinux: "AlmaLinux",
  arch: "Arch Linux",
  centos: "CentOS",
  debian: "Debian",
  fedora: "Fedora",
  linuxmint: "Linux Mint",
  opensuse: "openSUSE",
  "opensuse-leap": "openSUSE Leap",
  "opensuse-tumbleweed": "openSUSE Tumbleweed",
  pop: "Pop!_OS",
  rhel: "Red Hat Enterprise Linux",
  rocky: "Rocky Linux",
  sles: "SUSE Linux Enterprise",
  ubuntu: "Ubuntu",
};

function osLabel(osId: string, osVersion: string): string {
  if (!osId && !osVersion) return "Not reported yet";
  const name = osId ? (osNames[osId] ?? osId) : "Unknown OS";
  return osVersion ? `${name} ${osVersion}` : name;
}

export function DashboardView() {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canReadFleet = canPermission(principal, "fleet.read");
  const summary = useQuery({ ...fleetSummaryQueryOptions(lifetime), enabled: canReadFleet });
  const failure = summary.error ? toRpcFailure(summary.error) : null;
  // A failed refresh must not present a previous response as current evidence.
  const data = canReadFleet && !failure ? summary.data : undefined;
  const lifecycle = data?.lifecycle;
  const contact = data?.contact;
  const operatingSystems = data?.operatingSystems;
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

  const osRows = operatingSystems
    ? operatingSystems.groups.map(
        (group) => [osLabel(group.osId, group.osVersion), group.devices] as [string, bigint],
      )
    : [];
  if (operatingSystems && operatingSystems.otherDevices > 0n) {
    osRows.push(["Other", operatingSystems.otherDevices]);
  }
  const complianceRows: [string, bigint][] = compliance
    ? [
        ["Compliant", compliance.compliantResources],
        ["Drift fixed", compliance.driftRemediatedResources],
        ["Needs attention", compliance.attentionResources],
        ["Not checked recently", compliance.staleResources],
        ["Unknown", compliance.unknownResources],
      ]
    : [];

  const patchRows: [string, bigint][] = patch
    ? [
        ["Patched", patch.patchedDevices],
        ["Security pending", patch.securityPendingDevices],
        ["Reboot required", patch.rebootRequiredDevices],
        [`Stale (over ${patch.staleAfterSeconds / 3600} hours)`, patch.staleDevices],
        ["Unknown", patch.unknownDevices],
      ]
    : [];
  const findingRows: [string, bigint][] = findings
    ? [
        ["Critical", findings.criticalFindings],
        ["High", findings.highFindings],
        ["Medium", findings.mediumFindings],
        ["Low", findings.lowFindings],
        ["Other", findings.otherFindings],
      ]
    : [];
  // Workflow order, not a risk score. Never combine unlike populations.
  const next =
    approvals && approvals.pendingApprovals > 0n
      ? "approvals"
      : contact && contact.staleDevices > 0n && staleFilter
        ? "contact"
        : compliance &&
            (compliance.attentionResources > 0n ||
              compliance.staleResources > 0n ||
              compliance.unknownResources > 0n)
          ? "profiles"
          : findings &&
              (findings.unknownDevices > 0n ||
                findings.partialDevices > 0n ||
                findingRows.some(([, count]) => count > 0n))
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
            <div className="divide-y border-y">
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
                title="Security findings and coverage"
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
                        {findings.unknownDevices.toString()}
                      </strong>{" "}
                      active devices not checked · {findings.partialDevices.toString()} partly
                      checked · {findings.evaluatedDevices.toString()} checked.
                    </p>
                    <p>
                      {findings.criticalFindings.toString()} critical findings ·{" "}
                      {findings.highFindings.toString()} high findings.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Advisory summary" />
                )}
                <p className="text-xs text-muted-foreground">
                  Missing advisory coverage can hide exposure. Review sources and affected devices;
                  zero findings does not mean no exposure.
                </p>
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
                Up to ten newest actions in your device scopes. Sent is not proof of completion;
                open a device for results.
              </p>
            </div>
            {data.recentActions.length ? (
              <ul className="divide-y border-y">
                {data.recentActions.map((action) => (
                  <li
                    key={`${action.kind}:${action.actionId}`}
                    className="flex items-start gap-3 py-3"
                  >
                    <span className="flex size-8 shrink-0 items-center justify-center bg-muted text-muted-foreground">
                      {action.kind === "resource" ? (
                        <Settings2Icon className="size-4" aria-hidden="true" />
                      ) : action.kind === "device" ? (
                        <ServerIcon className="size-4" aria-hidden="true" />
                      ) : (
                        <ActivityIcon className="size-4" aria-hidden="true" />
                      )}
                    </span>
                    <div className="grid min-w-0 flex-1 gap-1">
                      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                        <span className="break-words text-sm font-medium">
                          {action.kind === "resource"
                            ? `Profile item · ${action.unit || "Unnamed item"}`
                            : (actionLabels[action.capability] ?? "Device action")}
                        </span>
                        <ActionRecord action={action} />
                      </div>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                        <Link
                          to="/devices/$deviceId"
                          params={{ deviceId: action.deviceId }}
                          search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                          className={linkClass}
                        >
                          Open device
                        </Link>
                        <span>{formatTimestamp(action.createdAt).local}</span>
                        <TechnicalDetails
                          items={[
                            { label: "Action ID", value: action.actionId },
                            { label: "Capability", value: action.capability },
                            { label: "Closed reason", value: action.closedReason },
                          ]}
                        />
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState
                title="No recorded actions in your device scopes"
                description="This is an action history, not confirmation that devices need no work."
              />
            )}
          </section>

          <section aria-labelledby="supporting-evidence-title" className="grid gap-3">
            <div>
              <h2 id="supporting-evidence-title" className="text-base font-semibold">
                Supporting fleet evidence
              </h2>
              <p className="text-xs text-muted-foreground">
                Exact counts in your authorized device scopes, not trends or a risk ranking.
              </p>
            </div>
            <div className="divide-y border-y">
              <Evidence
                title="Enrollment and contact"
                action={
                  <Link to="/devices" className={linkClass}>
                    Browse device records
                  </Link>
                }
              >
                {lifecycle ? (
                  <>
                    <p className="text-sm">
                      {lifecycle.totalDevices.toString()} devices in total. Enrolled does not mean
                      healthy.
                    </p>
                    <CountList
                      rows={[
                        ["Waiting to enroll", lifecycle.pendingDevices],
                        ["Enrolled", lifecycle.activeDevices],
                        ["Revoked", lifecycle.revokedDevices],
                        ["Recovery hold", lifecycle.recoveryHoldDevices],
                      ]}
                    />
                  </>
                ) : (
                  <Unavailable section="Enrollment state" />
                )}
                {contact ? (
                  <CountList
                    rows={[
                      [
                        `Seen within ${contact.staleAfterSeconds / 3600} hours`,
                        contact.recentDevices,
                      ],
                      [
                        `Last seen over ${contact.staleAfterSeconds / 3600} hours ago`,
                        contact.staleDevices,
                      ],
                      ["No recorded check-in", contact.unknownDevices],
                    ]}
                  />
                ) : (
                  <Unavailable section="Contact" />
                )}
              </Evidence>
              <Evidence
                title="Service compliance · profile items"
                action={
                  <Link to="/devices" className={linkClass}>
                    Inspect device services
                  </Link>
                }
              >
                {compliance ? (
                  <>
                    <p className="text-sm">
                      {compliance.totalResources.toString()} assigned profile items, not devices.
                    </p>
                    <CountList rows={complianceRows} />
                    <p className="text-xs text-muted-foreground">
                      {compliance.unassignedDevices.toString()} devices without a profile; not
                      counted as compliant.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Service compliance" />
                )}
              </Evidence>
              <Evidence
                title="Patch compliance · active devices"
                action={
                  <Link to="/devices" className={linkClass}>
                    Inspect device patch status
                  </Link>
                }
              >
                {patch ? (
                  <>
                    <CountList rows={patchRows} />
                    <p className="text-sm">
                      {patch.pendingSecurityUpdates.toString()} pending security updates ·{" "}
                      {patch.failedRunDevices.toString()} devices whose last update run failed.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Categories are disjoint. Reboot required means no security updates pending.
                      Pending updates and failed runs count fresh statuses only. Native
                      package-cache telemetry, not proof of installation; unknown includes
                      unavailable reports.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Patch compliance" />
                )}
              </Evidence>
              <Evidence
                title="Open findings · severity and coverage"
                action={
                  <Link to="/advisories" className={linkClass}>
                    Review advisories and sources
                  </Link>
                }
              >
                {findings ? (
                  <>
                    <CountList rows={findingRows} />
                    <p className="text-sm">
                      Active devices checked: {findings.evaluatedDevices.toString()} · partly
                      checked: {findings.partialDevices.toString()} · not checked:{" "}
                      {findings.unknownDevices.toString()}.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Counts findings, not devices. Accepted findings are excluded. Missing coverage
                      can hide exposure even when all severity counts are zero.
                    </p>
                  </>
                ) : (
                  <Unavailable section="Advisory" />
                )}
              </Evidence>
              <Evidence
                title="Operating systems · devices by version"
                action={
                  <Link to="/devices" className={linkClass}>
                    Browse and filter devices
                  </Link>
                }
              >
                {operatingSystems ? (
                  osRows.length ? (
                    <CountList rows={osRows} />
                  ) : (
                    <p className="text-sm">No devices in this OS summary.</p>
                  )
                ) : (
                  <Unavailable section="Operating system" />
                )}
                <p className="text-xs text-muted-foreground">
                  Latest reported OS and version. The twenty largest groups are shown; Other is the
                  exact remainder.
                </p>
              </Evidence>
            </div>
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

function Evidence({
  title,
  action,
  children,
}: {
  title: string;
  action: ReactNode;
  children: ReactNode;
}) {
  return (
    <div data-review-metric="" className="py-3">
      <details>
        <summary className="cursor-pointer text-sm font-medium">{title}</summary>
        <div className="mt-3 grid max-w-2xl gap-3">{children}</div>
      </details>
      <div className="mt-1">{action}</div>
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

function CountList({ rows }: { rows: [string, bigint][] }) {
  return (
    <dl className="grid gap-2 text-sm">
      {rows.map(([label, count]) => (
        <div key={label} className="flex items-center justify-between gap-3">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="font-medium tabular-nums">{count.toString()}</dd>
        </div>
      ))}
    </dl>
  );
}

function Unavailable({ section }: { section: string }) {
  return (
    <p data-review-state="blocked" className="text-sm text-muted-foreground">
      {section} unavailable. Review the linked evidence; no zero is assumed.
    </p>
  );
}

function ActionRecord({ action }: { action: FleetRecentAction }) {
  return (
    <Tooltip>
      <TooltipTrigger className="inline-flex min-h-6 items-center rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <StatusBadge
          status={action.outcomeUnknown ? "warning" : action.closedAt ? "neutral" : "info"}
        >
          {action.outcomeUnknown
            ? "Result unknown"
            : action.closedAt
              ? "Closed"
              : action.kind === "resource" && action.closedReason
                ? "Cancelling"
                : action.startAuthorizedAt
                  ? "Started"
                  : "Sent"}
        </StatusBadge>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm">
        <div className="grid gap-1 break-all">
          <p>Expires {formatTimestamp(action.expiresAt).local}</p>
          {action.closedAt ? (
            <p>Closed {formatTimestamp(action.closedAt).local}</p>
          ) : action.startAuthorizedAt ? (
            <p>Started {formatTimestamp(action.startAuthorizedAt).local}</p>
          ) : null}
        </div>
      </TooltipContent>
    </Tooltip>
  );
}
