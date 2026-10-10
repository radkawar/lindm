import { toJsonString } from "@bufbuild/protobuf";
import { ResourceDesiredStateSchema } from "../../../gen/lindm/resource/v1/resource_pb";
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Layers } from "lucide-react";
import {
  ResourceCompliance,
  ResourceDisposition,
  type ServiceActionSummary,
} from "../../../gen/lindm/admin/v1/assignments_pb";
import {
  ServiceExecutionFailure,
  ServiceExecutionState,
} from "../../../gen/lindm/agent/v1/service_execution_pb";
import { type ServiceObservation } from "../../../gen/lindm/agent/v1/service_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
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
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { ResourceAssignmentForm } from "./assignment-form";
import { resourceStateQueryOptions } from "./queries";

function enumLabel(value: string | undefined): string {
  return value?.toLowerCase().replaceAll("_", " ") ?? "Unknown";
}

export function DeviceResources({
  deviceId,
  emptyAction,
}: {
  deviceId: string;
  emptyAction?: ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const state = useQuery(resourceStateQueryOptions(lifetime, deviceId));
  const failure = state.error ? toRpcFailure(state.error) : null;
  const assignment = state.data?.assignment;
  return (
    <Card className="min-w-0" aria-busy={state.isFetching}>
      <CardHeader>
        <CardTitle>
          <h2>Resources</h2>
        </CardTitle>
        <CardDescription>
          Review the assigned profile, resource disposition and latest verified native results.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-5">
        <details className="text-xs text-muted-foreground">
          <summary className="w-fit cursor-pointer">How resource compliance is measured</summary>
          <p className="mt-2">
            Compliance reflects the latest verified result and its server-received age, not a live
            probe. Checks retain the last verification while running. Clearing an assignment records
            ownership-safe release work; pending, unsupported or conflicting cleanup remains
            visible.
          </p>
        </details>
        <Button
          className="w-fit"
          variant="outline"
          disabled={state.isFetching}
          onClick={() => void state.refetch()}
        >
          Refresh resource state
        </Button>
        {state.isPending ? (
          <div role="status" className="grid gap-3">
            <span className="text-sm text-muted-foreground">Loading resource state…</span>
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
        ) : null}
        {failure ? (
          <Alert variant="destructive">
            <AlertTitle>
              {failure.denied ? "Not authorized to read resources" : "Resource state unavailable"}
            </AlertTitle>
            <AlertDescription>
              {failure.codeName}: {failure.message}
              {state.data ? " Previously loaded state below may be stale." : ""}
            </AlertDescription>
          </Alert>
        ) : null}
        {state.data ? (
          <>
            <div className="grid gap-2 border bg-muted/30 p-4 text-sm">
              <h3 className="font-semibold">Current assignment</h3>
              {assignment ? (
                <>
                  <p>
                    {assignment.profileId
                      ? `${assignment.profileName} · revision ${assignment.revisionNumber.toString()}`
                      : "None — release state is recorded below"}
                  </p>
                  <p className="break-all">
                    Assigned by {assignment.actorId} at{" "}
                    {formatTimestamp(assignment.assignedAt).local}
                  </p>
                  <p className="whitespace-pre-wrap break-words">Reason: {assignment.reason}</p>
                  {assignment.profileId ? (
                    <p>Reconciliation interval: {assignment.reconcileIntervalSeconds} seconds</p>
                  ) : null}
                  <p className="break-all font-mono text-xs text-muted-foreground">
                    Assignment {assignment.assignmentId}
                  </p>
                </>
              ) : (
                <p>None — this device has never been assigned a resource profile.</p>
              )}
            </div>
            {state.data.resources.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Resource</TableHead>
                    <TableHead>Desired state</TableHead>
                    <TableHead>Compliance / verification</TableHead>
                    <TableHead>Disposition / reason</TableHead>
                    <TableHead>Latest action (history)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {state.data.resources.map((resource) => (
                    <TableRow key={resource.resourceId}>
                      <TableCell className="align-top font-mono">
                        {resource.desired?.state.case ?? "Unknown kind"} /{" "}
                        {resource.desired?.ref?.canonicalKey ?? "Not reported"}
                      </TableCell>
                      <TableCell className="align-top">
                        {resource.desired ? (
                          <details>
                            <summary className="cursor-pointer">Typed desired state</summary>
                            <pre className="mt-2 max-w-lg overflow-auto whitespace-pre-wrap break-all text-xs">
                              {toJsonString(ResourceDesiredStateSchema, resource.desired, {
                                prettySpaces: 2,
                              })}
                            </pre>
                          </details>
                        ) : (
                          "Not reported"
                        )}
                        <p className="mt-2 whitespace-normal">
                          Dependencies:{" "}
                          {resource.dependsOn.length === 0
                            ? "None"
                            : resource.dependsOn
                                .map(
                                  (dependency) =>
                                    `${dependency.ref?.kind ?? "Unknown"}/${dependency.ref?.canonicalKey ?? "Unknown"} (condition ${dependency.condition})`,
                                )
                                .join(", ")}
                        </p>
                      </TableCell>
                      <TableCell className="min-w-64 align-top">
                        <Badge
                          variant={
                            resource.compliance === ResourceCompliance.ATTENTION ||
                            resource.compliance === ResourceCompliance.STALE
                              ? "destructive"
                              : "secondary"
                          }
                        >
                          {resource.compliance === ResourceCompliance.UNSPECIFIED
                            ? "unknown"
                            : enumLabel(ResourceCompliance[resource.compliance])}
                        </Badge>
                        <p className="mt-2 whitespace-normal">
                          Last verified (server received):{" "}
                          {resource.lastVerifiedAt
                            ? formatTimestamp(resource.lastVerifiedAt).local
                            : "Not verified"}
                        </p>
                        <p className="mt-1 whitespace-normal">
                          Observed (device clock):{" "}
                          {resource.observedAt
                            ? formatTimestamp(resource.observedAt).local
                            : "Not reported"}
                        </p>
                      </TableCell>
                      <TableCell className="align-top">
                        <Badge
                          variant={
                            resource.disposition === ResourceDisposition.ATTENTION ||
                            resource.disposition === ResourceDisposition.BLOCKED ||
                            resource.disposition === ResourceDisposition.UNSUPPORTED
                              ? "destructive"
                              : "secondary"
                          }
                        >
                          {enumLabel(ResourceDisposition[resource.disposition])}
                        </Badge>
                        <p className="mt-2 whitespace-normal break-words">
                          {resource.reason || "—"}
                        </p>
                        {resource.disposition === ResourceDisposition.ATTENTION ? (
                          <p className="mt-2 whitespace-normal">
                            No automatic retry. Review the result and explicitly reassign to retry.
                          </p>
                        ) : null}
                      </TableCell>
                      <TableCell className="min-w-72 align-top">
                        <ActionHistory action={resource.latestAction} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="flex flex-col items-center gap-3 border border-dashed px-4 py-10 text-center">
                <span className="rounded-full bg-muted p-3 text-muted-foreground">
                  <Layers className="size-6" aria-hidden="true" />
                </span>
                <div className="space-y-1">
                  <p className="font-medium">No managed resources</p>
                  <p className="text-sm text-muted-foreground">
                    Assign a resource profile to define this device’s desired state.
                  </p>
                </div>
                {canPermission(principal, "resources.assign") ? emptyAction : null}
              </div>
            )}
            <div className="grid gap-2">
              <h3 className="font-semibold">Ownership-safe releases</h3>
              <p className="text-sm text-muted-foreground">
                Release is not an inverse desired state. Only owned changes may be restored;
                unsupported or conflicting cleanup must remain visible.
              </p>
              {state.data.releases.length === 0 ? (
                <p className="text-sm text-muted-foreground">No recorded release work.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Resource</TableHead>
                      <TableHead>State / reason</TableHead>
                      <TableHead>Assignment transition</TableHead>
                      <TableHead>Requested / completed</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {state.data.releases.map((release) => (
                      <TableRow key={release.releaseId}>
                        <TableCell className="font-mono">
                          {release.ref?.kind ?? "Unknown"} /{" "}
                          {release.ref?.canonicalKey ?? "Unknown"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{release.state || "Unknown"}</Badge>
                          <p className="mt-1 whitespace-normal">
                            {release.reason || "No reason reported"}
                          </p>
                        </TableCell>
                        <TableCell className="whitespace-normal break-all text-xs">
                          {release.sourceAssignmentId} → {release.supersedingAssignmentId}
                          <p>Release {release.releaseId}</p>
                        </TableCell>
                        <TableCell>
                          <p>{formatTimestamp(release.requestedAt).local}</p>
                          <p>
                            {release.completedAt
                              ? formatTimestamp(release.completedAt).local
                              : "Not completed"}
                          </p>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
            <div className="grid gap-2">
              <h3 className="font-semibold">Recent actions</h3>
              <p className="text-sm text-muted-foreground">
                Latest service actions across assignment heads.
              </p>
              <details className="text-xs text-muted-foreground">
                <summary className="w-fit cursor-pointer">Action history scope</summary>
                <p className="mt-2">
                  Up to 50 recent actions, newest first, including previous assignment heads. Signed
                  results are device-signed history, not live compliance. Issuance, authorization,
                  and closure are server records, not proof of a native effect.
                </p>
              </details>
              {state.data.recentActions.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Resource</TableHead>
                      <TableHead>Sequence</TableHead>
                      <TableHead>Assignment</TableHead>
                      <TableHead>Issued</TableHead>
                      <TableHead>Start authorized</TableHead>
                      <TableHead>Closed reason</TableHead>
                      <TableHead>Signed state / failure</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {state.data.recentActions.map((recent) => (
                      <TableRow
                        key={
                          recent.action?.actionId ?? `${recent.assignmentId}:${recent.resourceId}`
                        }
                      >
                        <TableCell className="font-mono">
                          {recent.ref?.kind ?? "Unknown"} /{" "}
                          {recent.ref?.canonicalKey ?? "Not reported"}
                        </TableCell>
                        <TableCell>{recent.action?.resourceSequence.toString() ?? "—"}</TableCell>
                        <TableCell>
                          <span className="font-mono" title={recent.assignmentId}>
                            {recent.assignmentId.slice(0, 8)}
                          </span>{" "}
                          <Badge variant="secondary">
                            {recent.assignmentId === assignment?.assignmentId
                              ? "current"
                              : "previous head"}
                          </Badge>
                        </TableCell>
                        <TableCell>{formatTimestamp(recent.action?.issuedAt).local}</TableCell>
                        <TableCell>
                          {formatTimestamp(recent.action?.startAuthorizedAt).local}
                        </TableCell>
                        <TableCell>{recent.action?.closedReason || "—"}</TableCell>
                        <TableCell>
                          {recent.action?.status ? (
                            <>
                              <p>{enumLabel(ServiceExecutionState[recent.action.status.state])}</p>
                              <p>
                                Failure:{" "}
                                {enumLabel(ServiceExecutionFailure[recent.action.status.failure])}
                              </p>
                            </>
                          ) : (
                            "No signed device history"
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <p className="border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
                  No recent actions.
                </p>
              )}
            </div>
          </>
        ) : null}
        {canPermission(principal, "resources.assign") ? (
          <ResourceAssignmentForm
            deviceId={deviceId}
            expectedAssignmentId={assignment?.assignmentId}
            stateReady={state.isSuccess && !failure}
          />
        ) : null}
      </CardContent>
    </Card>
  );
}

function ActionHistory({ action }: { action: ServiceActionSummary | undefined }) {
  if (!action) return <p>No action issued.</p>;
  const status = action.status;
  return (
    <div className="grid gap-1 whitespace-normal text-xs">
      <p>
        Sequence {action.resourceSequence.toString()} ·{" "}
        {status ? enumLabel(ServiceExecutionState[status.state]) : "Awaiting signed device history"}
      </p>
      <p className="break-all font-mono">{action.actionId}</p>
      <p>Failure: {status ? enumLabel(ServiceExecutionFailure[status.failure]) : "Not reported"}</p>
      <p>Issued (server): {formatTimestamp(action.issuedAt).local}</p>
      <p>Expires (server): {formatTimestamp(action.expiresAt).local}</p>
      <p>Start authorized (server): {formatTimestamp(action.startAuthorizedAt).local}</p>
      <p>Started (device clock): {formatTimestamp(status?.startedAt).local}</p>
      <p>Completed (device clock): {formatTimestamp(status?.completedAt).local}</p>
      {action.closedReason ? (
        <p>
          Closed (server): {action.closedReason} · {formatTimestamp(action.closedAt).local}
        </p>
      ) : null}
      {status ? (
        <>
          <p>
            Attested (device clock): {formatTimestamp(action.attestedAt).local} · received (server):{" "}
            {formatTimestamp(action.receivedAt).local} · evidence revision{" "}
            {action.actionRevision.toString()}
          </p>
          <details>
            <summary className="cursor-pointer">Before observation vs verification</summary>
            <div className="mt-2 grid gap-3">
              <Observation label="Before execution" observation={status.before} />
              <Observation
                label="Verification after execution"
                observation={status.verification?.observation}
              />
              {status.verification ? (
                <p>
                  Converged: {String(status.verification.converged)}; runtime matches:{" "}
                  {String(status.verification.runtimeMatches)}; enablement matches:{" "}
                  {String(status.verification.enablementMatches)}; definition matches:{" "}
                  {String(status.verification.definitionMatches)}.
                </p>
              ) : (
                <p>No verification reported.</p>
              )}
            </div>
          </details>
        </>
      ) : null}
    </div>
  );
}

function Observation({
  label,
  observation,
}: {
  label: string;
  observation: ServiceObservation | undefined;
}) {
  return (
    <div>
      <h4 className="font-semibold">{label}</h4>
      {observation ? (
        <>
          <p>Observed: {formatTimestamp(observation.observedAt).local}</p>
          <p>
            Load: {observation.loadState || "Not reported"}; active:{" "}
            {observation.activeState || "Not reported"}; substate:{" "}
            {observation.subState || "Not reported"}; unit file:{" "}
            {observation.unitFileState || "Not reported"}.
          </p>
          <p>
            Pending job: {String(observation.jobPending)}; daemon reload needed:{" "}
            {String(observation.needDaemonReload)}; transient: {String(observation.transient)}.
          </p>
          <p className="break-all">Boot {observation.bootId}</p>
        </>
      ) : (
        <p>Not reported.</p>
      )}
    </div>
  );
}

export function DeviceResourceComplianceBadge({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const state = useQuery(resourceStateQueryOptions(lifetime, deviceId));
  const data = state.error ? undefined : state.data;
  const resources = data?.resources ?? [];
  const pendingReleases = data?.releases.some((release) => !release.completedAt) ?? false;
  const attention = resources.some(
    (resource) => resource.compliance === ResourceCompliance.ATTENTION,
  );
  const unknown = resources.some(
    (resource) =>
      resource.compliance !== ResourceCompliance.COMPLIANT &&
      resource.compliance !== ResourceCompliance.DRIFT_REMEDIATED &&
      resource.compliance !== ResourceCompliance.ATTENTION &&
      resource.compliance !== ResourceCompliance.STALE,
  );
  const stale = resources.some((resource) => resource.compliance === ResourceCompliance.STALE);
  const compliant =
    resources.length > 0 &&
    resources.every(
      (resource) =>
        resource.compliance === ResourceCompliance.COMPLIANT ||
        resource.compliance === ResourceCompliance.DRIFT_REMEDIATED,
    );
  const remediated = resources.some(
    (resource) => resource.compliance === ResourceCompliance.DRIFT_REMEDIATED,
  );
  const label = attention
    ? "Resources need attention"
    : unknown
      ? "Compliance unknown"
      : stale
        ? "Resources stale"
        : compliant
          ? remediated
            ? "Resource drift remediated"
            : "Resources compliant"
          : data && resources.length === 0
            ? "Resources unassigned"
            : "Compliance unknown";
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Badge
            variant={
              pendingReleases
                ? "warning"
                : attention
                  ? "destructive"
                  : unknown
                    ? "outline"
                    : stale
                      ? "warning"
                      : compliant
                        ? "success"
                        : "outline"
            }
            tabIndex={0}
          />
        }
      >
        <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />
        {pendingReleases ? "Resource release pending" : label}
      </TooltipTrigger>
      <TooltipContent>
        Current assigned resources only, based on the latest verified results and server-received
        age, not a live probe or whole-device compliance. Pending releases are separate from
        compliance. Checks retain the last verification while running.
      </TooltipContent>
    </Tooltip>
  );
}
