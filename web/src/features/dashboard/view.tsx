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
import { Bar, BarChart, CartesianGrid, Pie, PieChart, XAxis, YAxis } from "recharts";
import type { FleetRecentAction } from "../../../gen/lindm/admin/v1/fleet_summary_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { formatTimestamp } from "@/lib/time";
import { fleetSummaryQueryOptions } from "./queries";
import { StaleDevices } from "./stale-devices";

const approvalHelp =
  "Requests waiting in your approval inbox. Another admin must approve each one before it runs.";

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
  const observed = formatTimestamp(data?.observedAt);

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
  const findingRows: [string, bigint][] = findings
    ? [
        ["Critical", findings.criticalFindings],
        ["High", findings.highFindings],
        ["Medium", findings.mediumFindings],
        ["Low", findings.lowFindings],
        ["Other", findings.otherFindings],
      ]
    : [];

  return (
    <section className="grid min-w-0 gap-5" aria-busy={summary.isFetching}>
      <PageHeader
        title="Dashboard"
        description="Your fleet at a glance."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              disabled={!canReadFleet || summary.isFetching}
              onClick={() => {
                if (!lifetime.signal.aborted) void summary.refetch();
              }}
            >
              <RefreshCwIcon aria-hidden="true" />
              {summary.isFetching ? "Refreshing…" : "Refresh"}
            </Button>
          </>
        }
      />

      {!canReadFleet ? (
        <Alert>
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
        <RpcError failure={failure} title="Couldn't load the fleet overview" />
      ) : summary.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading…
        </p>
      ) : null}

      {data ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Metric
              title="Enrolled"
              value={lifecycle?.activeDevices}
              detail={
                lifecycle
                  ? `${lifecycle.totalDevices.toString()} devices in total.`
                  : "Enrollment summary unavailable."
              }
              help="Devices that finished enrolling and can be managed. Being enrolled does not mean a device is healthy."
            />
            <Metric
              title="Waiting to enroll"
              value={lifecycle?.pendingDevices}
              detail="Started enrolling but not finished yet."
              help="These devices may be waiting for an admin to approve them. See Enrollment."
            />
            <Metric
              title="Not seen recently"
              value={contact?.staleDevices}
              detail={
                contact
                  ? `No check-in for over ${contact.staleAfterSeconds / 3600} hours.`
                  : "Check-in summary unavailable."
              }
              help="Devices that never checked in are counted as unknown, not here."
            />
            <Metric
              title="Approval requests"
              value={approvals?.pendingApprovals}
              detail={approvals ? "Waiting in your inbox." : "Approval summary unavailable."}
              help={approvalHelp}
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
            <span>
              Updated{" "}
              {observed.date ? (
                <time dateTime={observed.utc}>{observed.local}</time>
              ) : (
                observed.local
              )}
            </span>
            <Link to="/approvals" className={linkClass}>
              Review approvals <ArrowUpRightIcon className="size-3.5" aria-hidden="true" />
            </Link>
          </div>

          <div className="grid items-stretch gap-4 xl:grid-cols-3">
            <Panel
              title="Operating systems"
              description="Devices by operating system and version."
              help="From each device's latest report. The twenty largest groups are shown; Other contains the rest."
            >
              {operatingSystems ? (
                <DistributionChart kind="donut" rows={osRows} label="Devices" />
              ) : (
                <Unavailable section="Operating system" />
              )}
            </Panel>
            <Panel
              title="Service compliance"
              description="Profile items assigned to devices."
              help="Counts profile items, not devices. Devices without a profile are not counted as compliant. Open a device for details."
            >
              {compliance ? (
                <>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-semibold tabular-nums">
                      {compliance.totalResources.toString()}
                    </span>
                    <span className="text-xs text-muted-foreground">profile items</span>
                  </div>
                  <DistributionChart kind="stacked" rows={complianceRows} label="Resources" />
                  <p className="mt-auto text-xs text-muted-foreground">
                    {compliance.unassignedDevices.toString()} devices without a profile.
                  </p>
                </>
              ) : (
                <Unavailable section="Service compliance" />
              )}
            </Panel>
            <Panel
              title="Open security findings"
              description="Findings by severity."
              help="Counts findings, not devices. Accepted findings are not included. Missing advisory data can hide findings, so zero does not guarantee no exposure."
            >
              {findings ? (
                <>
                  <DistributionChart kind="severity" rows={findingRows} label="Findings" />
                  <p className="text-xs text-muted-foreground">
                    Devices checked: {findings.evaluatedDevices.toString()} · not checked:{" "}
                    {findings.unknownDevices.toString()}
                  </p>
                </>
              ) : (
                <Unavailable section="Advisory" />
              )}
              <Link to="/advisories" className={`${linkClass} mt-auto`}>
                Open advisories <ArrowUpRightIcon className="size-3.5" aria-hidden="true" />
              </Link>
            </Panel>
          </div>

          <div className="grid items-start gap-4 lg:grid-cols-2">
            <Panel
              title="Fleet status"
              description="Enrollment and last check-in."
              help="Last check-in is when the server last heard from each device."
            >
              <div className="grid gap-5 sm:grid-cols-2">
                <div className="grid content-start gap-3">
                  <h3 className="text-xs font-medium text-muted-foreground">Enrollment</h3>
                  {lifecycle ? (
                    <CountList
                      rows={[
                        ["Waiting to enroll", lifecycle.pendingDevices],
                        ["Enrolled", lifecycle.activeDevices],
                        ["Revoked", lifecycle.revokedDevices],
                        ["Recovery hold", lifecycle.recoveryHoldDevices],
                      ]}
                    />
                  ) : (
                    <Unavailable section="Enrollment state" />
                  )}
                </div>
                <div className="grid content-start gap-3">
                  <h3 className="text-xs font-medium text-muted-foreground">Last check-in</h3>
                  {contact ? (
                    <CountList
                      rows={[
                        [`Within ${contact.staleAfterSeconds / 3600} hours`, contact.recentDevices],
                        [`Over ${contact.staleAfterSeconds / 3600} hours`, contact.staleDevices],
                        ["Unknown", contact.unknownDevices],
                      ]}
                    />
                  ) : (
                    <Unavailable section="Contact" />
                  )}
                </div>
              </div>
              <Link to="/devices" className={linkClass}>
                Browse devices <ArrowUpRightIcon className="size-3.5" aria-hidden="true" />
              </Link>
            </Panel>
            {data.observedAt && contact ? (
              <StaleDevices
                observedAt={data.observedAt}
                staleAfterSeconds={contact.staleAfterSeconds}
                staleTotal={contact.staleDevices}
              />
            ) : (
              <Unavailable section="Stale device list" />
            )}
          </div>

          <Panel
            title="Recent activity"
            description="Latest actions sent to devices."
            help="The ten most recent actions. A sent action is not proof the device carried it out; open the device for results."
          >
            {data.recentActions.length ? (
              <ul className="divide-y">
                {data.recentActions.map((action) => (
                  <li
                    key={`${action.kind}:${action.actionId}`}
                    className="flex items-start gap-3 py-3 first:pt-0 last:pb-0"
                  >
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
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
                        <span className="break-all text-sm font-medium">
                          {action.kind === "resource"
                            ? `Profile item · ${action.unit || "Unnamed item"}`
                            : action.kind === "device"
                              ? action.capability || "Device action"
                              : "Action"}
                        </span>
                        <ActionRecord action={action} />
                      </div>
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                        <Link
                          to="/devices/$deviceId"
                          params={{ deviceId: action.deviceId }}
                          search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                          className="max-w-full truncate underline-offset-4 hover:text-foreground hover:underline"
                          title={action.deviceId}
                        >
                          Open device
                        </Link>
                        <span>· {formatTimestamp(action.createdAt).local}</span>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState
                title="No recent actions"
                description="Actions you send to devices appear here."
              />
            )}
          </Panel>
        </>
      ) : null}
    </section>
  );
}

const linkClass =
  "inline-flex items-center gap-1 text-xs font-medium text-foreground underline-offset-4 hover:underline";

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

function Panel({
  title,
  description,
  help,
  children,
}: {
  title: string;
  description: string;
  help: string;
  children: ReactNode;
}) {
  return (
    <Card className="min-w-0">
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <CardTitle>
            <h2>{title}</h2>
          </CardTitle>
          <Help label={`About ${title.toLowerCase()}`}>{help}</Help>
        </div>
        <CardDescription className="text-xs">{description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-4">{children}</CardContent>
    </Card>
  );
}

function Metric({
  title,
  value,
  detail,
  help,
}: {
  title: string;
  value: bigint | undefined;
  detail: string;
  help: string;
}) {
  return (
    <Card size="sm" className="gap-1">
      <CardHeader className="flex items-center justify-between gap-2">
        <CardDescription className="text-xs font-medium">{title}</CardDescription>
        <Help label={`About ${title.toLowerCase()}`}>{help}</Help>
      </CardHeader>
      <CardContent className="grid gap-1">
        <p className="text-2xl font-semibold tracking-tight tabular-nums">
          {value?.toString() ?? "Unavailable"}
        </p>
        <p className="text-xs text-muted-foreground">{detail}</p>
      </CardContent>
    </Card>
  );
}

function DistributionChart({
  rows,
  kind,
  label,
}: {
  rows: [string, bigint][];
  kind: "donut" | "stacked" | "severity";
  label: string;
}) {
  const points = rows.map(([name, count], index) => ({
    name,
    count: Number(count),
    exact: count.toString(),
    key: `group${index}`,
    fill: `var(--chart-${(index % 5) + 1})`,
  }));
  const config: ChartConfig = Object.fromEntries(
    points.map((point) => [
      point.key,
      {
        label: point.name,
        color: point.fill,
      },
    ]),
  );
  const total = rows.reduce((sum, [, count]) => sum + count, 0n);
  const tooltip = (
    <ChartTooltipContent
      hideLabel
      formatter={(_value, name) => {
        const point = points.find((item) => item.key === name || item.name === name);
        return (
          <span className="flex w-full items-center justify-between gap-4">
            <span className="text-muted-foreground">{point?.name ?? name}</span>
            <span className="font-mono font-medium tabular-nums">
              {point?.exact ?? "Unavailable"}
            </span>
          </span>
        );
      }}
    />
  );

  return (
    <div className="grid gap-3">
      {total === 0n ? (
        <EmptyState title={`No ${label.toLowerCase()} in this summary`} />
      ) : kind === "donut" ? (
        <div className="relative">
          <ChartContainer
            config={config}
            className="mx-auto h-44 w-full"
            aria-label={`${label} by operating system and version`}
          >
            <PieChart>
              <ChartTooltip content={tooltip} />
              <Pie
                data={points}
                dataKey="count"
                nameKey="name"
                innerRadius={55}
                outerRadius={78}
                strokeWidth={2}
                isAnimationActive={false}
              />
            </PieChart>
          </ChartContainer>
          <div
            className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center"
            aria-hidden="true"
          >
            <span className="text-xl font-semibold tabular-nums">{total.toString()}</span>
            <span className="text-xs text-muted-foreground">devices</span>
          </div>
        </div>
      ) : kind === "stacked" ? (
        <ChartContainer
          config={config}
          className="h-20 w-full"
          aria-label="Service resource compliance distribution"
        >
          <BarChart
            accessibilityLayer
            layout="vertical"
            data={[Object.fromEntries(points.map((point) => [point.key, point.count]))]}
            margin={{ top: 12, right: 0, bottom: 12, left: 0 }}
          >
            <XAxis type="number" hide />
            <YAxis type="category" hide />
            <ChartTooltip content={tooltip} cursor={false} />
            {points.map((point) => (
              <Bar
                key={point.key}
                dataKey={point.key}
                stackId="resources"
                fill={`var(--color-${point.key})`}
                barSize={36}
                isAnimationActive={false}
              />
            ))}
          </BarChart>
        </ChartContainer>
      ) : (
        <ChartContainer
          config={config}
          className="h-44 w-full"
          aria-label="Open findings by severity"
        >
          <BarChart
            accessibilityLayer
            data={points}
            margin={{ top: 8, right: 4, bottom: 0, left: -24 }}
          >
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="name"
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              interval={0}
              fontSize={10}
            />
            <YAxis allowDecimals={false} tickLine={false} axisLine={false} fontSize={10} />
            <ChartTooltip
              content={
                <ChartTooltipContent
                  hideLabel
                  formatter={(_value, _name, item) => {
                    const point = points.find((point) => point.name === item.payload.name);
                    return (
                      <span className="flex w-full items-center justify-between gap-4">
                        <span className="text-muted-foreground">{point?.name}</span>
                        <span className="font-mono font-medium tabular-nums">
                          {point?.exact ?? "Unavailable"}
                        </span>
                      </span>
                    );
                  }}
                />
              }
              cursor={false}
            />
            <Bar dataKey="count" maxBarSize={40} isAnimationActive={false} />
          </BarChart>
        </ChartContainer>
      )}
      <dl
        className={`grid gap-x-4 gap-y-2 text-xs ${kind === "stacked" ? "" : "grid-cols-2"} ${kind === "donut" ? "max-h-32 overflow-y-auto" : ""}`}
      >
        {points.map((point) => (
          <div key={point.key} className="flex min-w-0 items-center justify-between gap-2">
            <dt className="flex min-w-0 items-center gap-1.5">
              <span
                className="size-2 shrink-0 rounded-sm"
                style={{ backgroundColor: point.fill }}
                aria-hidden="true"
              />
              <span className="break-words text-muted-foreground">{point.name}</span>
            </dt>
            <dd className="shrink-0 font-medium tabular-nums">{point.exact}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function CountList({ rows }: { rows: [string, bigint][] }) {
  return (
    <dl className="grid gap-2 text-xs">
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
  return <p className="text-xs text-muted-foreground">{section} unavailable.</p>;
}

function ActionRecord({ action }: { action: FleetRecentAction }) {
  return (
    <Tooltip>
      <TooltipTrigger
        className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-label="Server action record details"
      >
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
          {action.closedReason ? <p>{action.closedReason}</p> : null}
          {action.closedAt ? (
            <p>Closed {formatTimestamp(action.closedAt).local}</p>
          ) : action.startAuthorizedAt ? (
            <p>Started {formatTimestamp(action.startAuthorizedAt).local}</p>
          ) : null}
          <p className="font-mono text-xs">Action ID {action.actionId}</p>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}
