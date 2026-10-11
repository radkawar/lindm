import { toJsonString } from "@bufbuild/protobuf";
import {
  ResourceDesiredStateSchema,
  ResourceObservationSchema,
  VerificationDisposition,
  type ResourceObservation,
} from "../../../gen/lindm/resource/v1/resource_pb";
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import {
  ResourceCompliance,
  ResourceDisposition,
  type ServiceActionSummary,
} from "../../../gen/lindm/admin/v1/assignments_pb";
import {
  ResourceExecutionFailure,
  ResourceExecutionState,
} from "../../../gen/lindm/agent/v1/service_execution_pb";
import type { SystemdServiceObservation } from "../../../gen/lindm/resource/v1/observations_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { EmptyState } from "@/components/ui/empty-state";
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
import { blockedReasonLabel, toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { ResourceAssignmentForm } from "./assignment-form";
import { resourceStateQueryOptions } from "./queries";

function enumLabel(value: string | undefined): string {
  if (!value) return "Unknown";
  const label = value.toLowerCase().replaceAll("_", " ");
  return label.charAt(0).toUpperCase() + label.slice(1);
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
          <RpcError failure={failure} title="Service state unavailable">
            {state.data ? <p>Previously loaded state below may be stale.</p> : null}
          </RpcError>
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
                      : "None. Release state is recorded below."}
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
                <p>No resource profile has been assigned to this device.</p>
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
                        <StatusBadge
                          status={
                            resource.compliance === ResourceCompliance.ATTENTION
                              ? "destructive"
                              : resource.compliance === ResourceCompliance.STALE
                                ? "warning"
                                : resource.compliance === ResourceCompliance.COMPLIANT ||
                                    resource.compliance === ResourceCompliance.DRIFT_REMEDIATED
                                  ? "success"
                                  : "neutral"
                          }
                        >
                          {resource.compliance === ResourceCompliance.UNSPECIFIED
                            ? "Unknown"
                            : enumLabel(ResourceCompliance[resource.compliance])}
                        </StatusBadge>
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
                        <StatusBadge
                          status={
                            resource.disposition === ResourceDisposition.ATTENTION
                              ? "destructive"
                              : resource.disposition === ResourceDisposition.BLOCKED
                                ? "warning"
                                : resource.disposition === ResourceDisposition.SUCCEEDED
                                  ? "success"
                                  : resource.disposition === ResourceDisposition.IN_PROGRESS
                                    ? "info"
                                    : "neutral"
                          }
                        >
                          {enumLabel(ResourceDisposition[resource.disposition])}
                        </StatusBadge>
                        <p className="mt-2 whitespace-normal break-words">
                          {resource.reason
                            ? blockedReasonLabel(resource.reason)
                            : "No reason reported"}
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
              <EmptyState
                title="No managed resources"
                description="Assign a resource profile to define this device's desired state."
                action={canPermission(principal, "resources.assign") ? emptyAction : undefined}
              />
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
                          <StatusBadge status={release.completedAt ? "success" : "warning"}>
                            {enumLabel(release.state)}
                          </StatusBadge>
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
                        <TableCell>
                          {recent.action?.resourceSequence.toString() ?? "Not reported"}
                        </TableCell>
                        <TableCell>
                          <span className="font-mono" title={recent.assignmentId}>
                            {recent.assignmentId.slice(0, 8)}
                          </span>{" "}
                          <StatusBadge status="neutral">
                            {recent.assignmentId === assignment?.assignmentId
                              ? "Current"
                              : "Previous assignment"}
                          </StatusBadge>
                        </TableCell>
                        <TableCell>{formatTimestamp(recent.action?.issuedAt).local}</TableCell>
                        <TableCell>
                          {formatTimestamp(recent.action?.startAuthorizedAt).local}
                        </TableCell>
                        <TableCell>
                          {recent.action?.closedReason
                            ? recent.action.closedAt
                              ? recent.action.closedReason
                              : `Cancellation requested: ${recent.action.closedReason}`
                            : "Not closed"}
                        </TableCell>
                        <TableCell>
                          {recent.action?.status ? (
                            <>
                              <ResourceExecutionStatus
                                state={recent.action.status.state}
                                verification={recent.action.status.verification?.disposition}
                              />
                              <p>
                                Failure:{" "}
                                {enumLabel(ResourceExecutionFailure[recent.action.status.failure])}
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

function ResourceExecutionStatus({
  state,
  verification,
}: {
  state: ResourceExecutionState | undefined;
  verification?: VerificationDisposition;
}) {
  if (
    state === ResourceExecutionState.SUCCEEDED &&
    verification === VerificationDisposition.NOT_APPLICABLE
  ) {
    return <StatusBadge status="neutral">Released, not applicable</StatusBadge>;
  }
  return (
    <StatusBadge
      status={
        state === ResourceExecutionState.FAILED || state === ResourceExecutionState.OUTCOME_UNKNOWN
          ? "destructive"
          : state === ResourceExecutionState.SUCCEEDED
            ? "success"
            : state === ResourceExecutionState.RUNNING || state === ResourceExecutionState.PREPARING
              ? "info"
              : "neutral"
      }
    >
      {state === undefined
        ? "Awaiting signed device history"
        : enumLabel(ResourceExecutionState[state])}
    </StatusBadge>
  );
}

function ActionHistory({ action }: { action: ServiceActionSummary | undefined }) {
  if (!action) return <p>No action issued.</p>;
  const status = action.status;
  const checks =
    status?.verification?.checks.case === "systemdService"
      ? status.verification.checks.value
      : undefined;
  return (
    <div className="grid gap-1 whitespace-normal text-xs">
      <p>
        Sequence {action.resourceSequence.toString()} ·{" "}
        <ResourceExecutionStatus
          state={status?.state}
          verification={status?.verification?.disposition}
        />
      </p>
      <p className="break-all font-mono">{action.actionId}</p>
      <p>
        Failure: {status ? enumLabel(ResourceExecutionFailure[status.failure]) : "Not reported"}
      </p>
      {status?.state === ResourceExecutionState.PREPARING ? (
        <p>Preparing native transaction. No start authority or native verification yet.</p>
      ) : status?.preparationOutcome ? (
        <p>Preparation ended without a native effect. No native verification was produced.</p>
      ) : null}
      {status?.readOnly ? (
        <p>
          Read-only verification:{" "}
          {enumLabel(
            VerificationDisposition[
              status.verification?.disposition ?? VerificationDisposition.UNSPECIFIED
            ],
          )}
          . No native effect was authorized.
        </p>
      ) : null}
      <p>Issued (server): {formatTimestamp(action.issuedAt).local}</p>
      <p>Expires (server): {formatTimestamp(action.expiresAt).local}</p>
      <p>Start authorized (server): {formatTimestamp(action.startAuthorizedAt).local}</p>
      <p>Started (device clock): {formatTimestamp(status?.startedAt).local}</p>
      <p>Completed (device clock): {formatTimestamp(status?.completedAt).local}</p>
      {action.closedReason ? (
        <p>
          {action.closedAt ? "Closed (server)" : "Cancellation requested"}: {action.closedReason}
          {action.closedAt ? ` · ${formatTimestamp(action.closedAt).local}` : ""}
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
                observation={status.verification?.after}
              />
              {status.verification ? (
                <div>
                  <p>
                    Verification:{" "}
                    {enumLabel(VerificationDisposition[status.verification.disposition])}
                  </p>
                  {checks ? (
                    <p>
                      Runtime matches: {String(checks.runtimeMatches)}; enablement matches:{" "}
                      {String(checks.enablementMatches)}; definition matches:{" "}
                      {String(checks.definitionMatches)}.
                    </p>
                  ) : null}
                </div>
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
  observation: ResourceObservation | undefined;
}) {
  if (observation?.observed.case === "systemdService") {
    return <SystemdObservation label={label} observation={observation.observed.value} />;
  }
  return (
    <div>
      <h4 className="font-semibold">{label}</h4>
      {observation ? (
        <>
          <p>Observed: {formatTimestamp(observation.metadata?.observedAt).local}</p>
          <p className="break-all">Resource: {observation.ref?.canonicalKey || "Not reported"}</p>
          <details>
            <summary className="cursor-pointer">Advanced: view observation JSON</summary>
            <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all">
              {toJsonString(ResourceObservationSchema, observation, { prettySpaces: 2 })}
            </pre>
          </details>
        </>
      ) : (
        <p>Not reported.</p>
      )}
    </div>
  );
}

function SystemdObservation({
  label,
  observation,
}: {
  label: string;
  observation: SystemdServiceObservation | undefined;
}) {
  return (
    <div>
      <h4 className="font-semibold">{label}</h4>
      {observation ? (
        <>
          <p>Observed: {formatTimestamp(observation.observedAt).local}</p>
          <div className="flex flex-wrap items-center gap-2">
            <span>Load:</span>
            <StatusBadge status="neutral">{observation.loadState || "Not reported"}</StatusBadge>
            <span>Active:</span>
            <StatusBadge status={observation.activeState === "failed" ? "destructive" : "neutral"}>
              {observation.activeState || "Not reported"}
            </StatusBadge>
            <span>Substate:</span>
            <StatusBadge status="neutral">{observation.subState || "Not reported"}</StatusBadge>
            <span>Unit file:</span>
            <StatusBadge status="neutral">
              {observation.unitFileState || "Not reported"}
            </StatusBadge>
          </div>
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
  if (state.error) {
    return <RpcError failure={toRpcFailure(state.error)} title="Service compliance unavailable" />;
  }
  const data = state.data;
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
          <StatusBadge
            dot
            status={
              pendingReleases
                ? "warning"
                : attention
                  ? "destructive"
                  : unknown
                    ? "neutral"
                    : stale
                      ? "warning"
                      : compliant
                        ? "success"
                        : "neutral"
            }
            tabIndex={0}
          />
        }
      >
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
