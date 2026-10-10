import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ActivityIcon,
  ArrowUpRightIcon,
  ChartNoAxesCombinedIcon,
  InfoIcon,
  RefreshCwIcon,
  ServerIcon,
  Settings2Icon,
} from "lucide-react";
import type { ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Pie, PieChart, XAxis, YAxis } from "recharts";
import type { FleetRecentAction } from "../../../gen/lindm/admin/v1/fleet_summary_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
  "Pending, unexpired requests visible through your approval inbox, not a global count or a grant to approve. Action-specific permissions and approval-management scopes apply independently of fleet.read. The server rechecks authority, scope, separation of duties and expiry at decision or execution. This inbox is authorized and read separately from the fleet evidence time.";

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
  const compliance = data?.serviceCompliance;
  const findings = data?.findings;
  const approvals = data?.approvals;
  const observed = formatTimestamp(data?.observedAt);

  const osRows = operatingSystems
    ? operatingSystems.groups.map(
        (group) =>
          [
            `${group.osId || "Not reported"} · ${group.osVersion || "Not reported"}`,
            group.devices,
          ] as [string, bigint],
      )
    : [];
  if (operatingSystems && operatingSystems.otherDevices > 0n) {
    osRows.push(["Other OS/version groups", operatingSystems.otherDevices]);
  }
  const complianceRows: [string, bigint][] = compliance
    ? [
        ["Compliant", compliance.compliantResources],
        ["Drift remediated", compliance.driftRemediatedResources],
        ["Attention", compliance.attentionResources],
        ["Stale", compliance.staleResources],
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
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid gap-1">
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <div className="flex items-center gap-1 text-sm text-muted-foreground">
            <p>Your fleet at a glance.</p>
            <Help label="About fleet counts">
              Server-calculated counts cover every device in your authorized scope, not an
              inventory-page sample. Counts describe recorded evidence, not live presence.
            </Help>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={!canReadFleet || summary.isFetching}
          onClick={() => {
            if (!lifetime.signal.aborted) void summary.refetch();
          }}
        >
          <RefreshCwIcon aria-hidden="true" />
          Refresh
        </Button>
      </header>

      {!canReadFleet ? (
        <Alert>
          <AlertTitle>Fleet overview unavailable</AlertTitle>
          <AlertDescription>
            Fleet read permission is required for this overview. An unavailable summary is not an
            empty fleet. Open{" "}
            <Link to="/approvals" className="underline">
              Approvals
            </Link>{" "}
            separately to check whether your session can view an inbox.
          </AlertDescription>
        </Alert>
      ) : failure ? (
        <Alert variant="destructive">
          <AlertTitle>{failure.denied ? "Not authorized" : "Fleet summary unavailable"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : summary.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading fleet summary…
        </p>
      ) : null}

      {data ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Metric
              title="Devices"
              value={lifecycle?.totalDevices}
              detail="Across all enrollment states."
              help="Exact device count across every enrollment state in your fleet.read-authorized scope."
            />
            <Metric
              title="Active enrollments"
              value={lifecycle?.activeDevices}
              detail="Currently enrolled devices."
              help="Active describes enrollment lifecycle only. It does not establish online presence, device health or compliance."
            />
            <Metric
              title="Stale contact"
              value={contact?.staleDevices}
              detail={
                contact
                  ? `No contact in over ${contact.staleAfterSeconds / 3600} hours.`
                  : "Contact summary unavailable."
              }
              help="Server receipt times across all authorized enrollment states, evaluated at the fleet evidence time. Missing contact remains unknown and is not counted as stale. The exact threshold is included in recent contact."
            />
            <Metric
              title="Pending approvals"
              value={approvals?.pendingApprovals}
              detail={
                approvals ? "Unexpired requests in your inbox." : "Approval summary unavailable."
              }
              help={approvalHelp}
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
            <span>
              Evidence as of{" "}
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
              description="Devices by observed OS and version."
              help="Latest successful host observations across your authorized fleet. The twenty largest OS/version groups are shown; Other is the exact count in all remaining groups. Missing OS or version is shown as Not reported. An observation is not proof of current inventory freshness."
            >
              {operatingSystems ? (
                <DistributionChart kind="donut" rows={osRows} label="Devices" />
              ) : (
                <Unavailable section="Operating system" />
              )}
            </Panel>
            <Panel
              title="Service compliance"
              description="Current assigned service resources."
              help="Exact service-resource counts for current enrollment-generation assignment heads, not a device compliance rate. Devices without assigned resources are not counted as compliant. Open a device for verification times, dependencies, native evidence and action history."
            >
              {compliance ? (
                <>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-semibold tabular-nums">
                      {compliance.totalResources.toString()}
                    </span>
                    <span className="text-xs text-muted-foreground">assigned resources</span>
                  </div>
                  <DistributionChart kind="stacked" rows={complianceRows} label="Resources" />
                  <p className="mt-auto text-xs text-muted-foreground">
                    {compliance.unassignedDevices.toString()} devices without assigned resources.
                  </p>
                </>
              ) : (
                <Unavailable section="Service compliance" />
              )}
            </Panel>
            <Panel
              title="Open advisory findings"
              description="Affected findings by severity."
              help="Canonical affected findings across your fleet scope, not distinct devices. Other includes unspecified severity. Accepted and unknown findings are excluded, not considered fixed. Distro package coverage is not a complete vulnerability assessment. Evaluated does not mean unaffected; zero open findings does not establish that devices are clean. Stale or unsupported evidence remains unknown."
            >
              {findings ? (
                <>
                  <DistributionChart kind="severity" rows={findingRows} label="Findings" />
                  <p className="text-xs text-muted-foreground">
                    Active devices: {findings.evaluatedDevices.toString()} evaluated ·{" "}
                    {findings.unknownDevices.toString()} unknown
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
              description="Enrollment and recorded contact."
              help="Exact device counts across your fleet scope. Active enrollment does not establish compliance or connectivity. Contact uses server receipt times across all enrollment states; recent contact is not proof of inventory freshness or live presence. Age is evaluated at the displayed fleet evidence time, with the exact threshold included in recent contact. Missing contact remains unknown."
            >
              <div className="grid gap-5 sm:grid-cols-2">
                <div className="grid content-start gap-3">
                  <h3 className="text-xs font-medium text-muted-foreground">Enrollment</h3>
                  {lifecycle ? (
                    <CountList
                      rows={[
                        ["Pending", lifecycle.pendingDevices],
                        ["Active", lifecycle.activeDevices],
                        ["Revoked", lifecycle.revokedDevices],
                        ["Recovery hold", lifecycle.recoveryHoldDevices],
                      ]}
                    />
                  ) : (
                    <Unavailable section="Enrollment state" />
                  )}
                </div>
                <div className="grid content-start gap-3">
                  <h3 className="text-xs font-medium text-muted-foreground">Last contact</h3>
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
            description="Latest device and service action records."
            help="Newest ten action records across all fleet.read-authorized devices and enrollment generations, ordered by issue time, action ID and kind. This bounded history is not used for aggregates. Server issuance, start authorization and closure are not native execution proof. An unknown outcome must not be treated as success or retried blindly. Open a device for protected results; no action payloads or recovery secrets are included here."
          >
            {data.recentActions.length ? (
              <ul className="divide-y">
                {data.recentActions.map((action) => (
                  <li
                    key={`${action.kind}:${action.actionId}`}
                    className="flex items-start gap-3 py-3 first:pt-0 last:pb-0"
                  >
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                      {action.kind === "service" ? (
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
                          {action.kind === "service"
                            ? `Service action · ${action.unit || action.resourceId || "Resource not recorded"}`
                            : action.kind === "device"
                              ? action.capability || "Capability not recorded"
                              : "Unknown action kind"}
                        </span>
                        <ActionRecord action={action} />
                      </div>
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                        <Link
                          to="/devices/$deviceId"
                          params={{ deviceId: action.deviceId }}
                          search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                          className="max-w-full truncate underline-offset-4 hover:text-foreground hover:underline"
                        >
                          {action.deviceId}
                        </Link>
                        <span>· {formatTimestamp(action.createdAt).local}</span>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="flex items-center gap-3 py-4 text-sm text-muted-foreground">
                <ActivityIcon className="size-5" aria-hidden="true" />
                <p>No action records in your authorized fleet scope.</p>
              </div>
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
        <div className="flex h-36 flex-col items-center justify-center gap-2 text-muted-foreground">
          <ChartNoAxesCombinedIcon className="size-6" aria-hidden="true" />
          <p className="text-xs">No {label.toLowerCase()} in this summary.</p>
        </div>
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
            <Bar dataKey="count" radius={[3, 3, 0, 0]} maxBarSize={40} isAnimationActive={false} />
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
  return <p className="text-xs text-muted-foreground">{section} summary unavailable, not zero.</p>;
}

function ActionRecord({ action }: { action: FleetRecentAction }) {
  return (
    <Tooltip>
      <TooltipTrigger
        className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-label="Server action record details"
      >
        <Badge variant={action.outcomeUnknown ? "destructive" : "outline"} className="text-xs">
          {action.outcomeUnknown
            ? "Outcome unknown"
            : action.closedAt || action.closedReason
              ? "Closed"
              : action.startAuthorizedAt
                ? "Start authorized"
                : "Issued"}
        </Badge>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm">
        <div className="grid gap-1 break-all">
          <p>
            {action.kind === "service"
              ? "Service action"
              : action.kind === "device"
                ? "Device action"
                : "Unknown action kind"}{" "}
            · {action.actionId}
          </p>
          <p>Expires {formatTimestamp(action.expiresAt).local}</p>
          {action.closedReason ? <p>{action.closedReason}</p> : null}
          {action.closedAt ? (
            <p>Closed {formatTimestamp(action.closedAt).local}</p>
          ) : action.startAuthorizedAt ? (
            <p>Authorized {formatTimestamp(action.startAuthorizedAt).local}</p>
          ) : null}
          <p>
            Server record, not native execution proof. Unknown outcomes are not success; do not
            retry blindly.
          </p>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}
