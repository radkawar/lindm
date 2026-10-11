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
import { TechnicalDetails } from "@/components/ui/technical-details";
import { resourceStateQueryOptions } from "./queries";

function enumLabel(value: string | undefined): string {
  if (!value) return "Unknown";
  const label = value.toLowerCase().replaceAll("_", " ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

const complianceLabels: Partial<Record<ResourceCompliance, string>> = {
  [ResourceCompliance.COMPLIANT]: "Compliant",
  [ResourceCompliance.DRIFT_REMEDIATED]: "Drift fixed",
  [ResourceCompliance.ATTENTION]: "Needs attention",
  [ResourceCompliance.STALE]: "Not checked recently",
};

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
          <h2>Services and settings</h2>
        </CardTitle>
        <CardDescription>
          The profile assigned to this device and the latest result for each item.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-5">
        <Button
          className="w-fit"
          variant="outline"
          disabled={state.isFetching}
          onClick={() => void state.refetch()}
        >
          Refresh
        </Button>
        {state.isPending ? (
          <div role="status" className="grid gap-3">
            <span className="text-sm text-muted-foreground">Loading…</span>
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
        ) : null}
        {failure ? (
          <RpcError failure={failure} title="Couldn't load services">
            {state.data ? <p>The results below may be out of date.</p> : null}
          </RpcError>
        ) : null}
        {state.data ? (
          <>
            <div className="grid gap-2 border bg-muted/30 p-4 text-sm">
              <h3 className="font-semibold">Assigned profile</h3>
              {assignment?.profileId ? (
                <>
                  <p>
                    {assignment.profileName} (revision {assignment.revisionNumber.toString()})
                  </p>
                  <p className="break-words text-muted-foreground">
                    Assigned by {assignment.actorId} on{" "}
                    {formatTimestamp(assignment.assignedAt).local}. Checked every{" "}
                    {Math.round(assignment.reconcileIntervalSeconds / 60)} minutes.
                  </p>
                  <p className="whitespace-pre-wrap break-words text-muted-foreground">
                    Reason: {assignment.reason}
                  </p>
                </>
              ) : assignment ? (
                <>
                  <p>None. The profile was removed.</p>
                  <p className="whitespace-pre-wrap break-words text-muted-foreground">
                    Removed by {assignment.actorId} on{" "}
                    {formatTimestamp(assignment.assignedAt).local}. Reason: {assignment.reason}
                  </p>
                </>
              ) : (
                <p>No profile assigned.</p>
              )}
              <TechnicalDetails
                items={[{ label: "Assignment ID", value: assignment?.assignmentId }]}
              />
            </div>
            {state.data.resources.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Item</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead>Latest change</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {state.data.resources.map((resource) => (
                    <TableRow key={resource.resourceId}>
                      <TableCell className="align-top">
                        <p className="font-medium break-all">
                          {resource.desired?.ref?.canonicalKey ?? "Unnamed item"}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {resource.desired?.state.case ?? "Unknown type"}
                        </p>
                        {resource.dependsOn.length ? (
                          <p className="mt-1 whitespace-normal text-xs text-muted-foreground">
                            Depends on{" "}
                            {resource.dependsOn
                              .map((dependency) => dependency.ref?.canonicalKey ?? "Unknown")
                              .join(", ")}
                          </p>
                        ) : null}
                        {resource.desired ? (
                          <TechnicalDetails summary="Settings" items={[]}>
                            <pre className="mt-2 max-w-lg overflow-auto whitespace-pre-wrap break-all">
                              {toJsonString(ResourceDesiredStateSchema, resource.desired, {
                                prettySpaces: 2,
                              })}
                            </pre>
                          </TechnicalDetails>
                        ) : null}
                      </TableCell>
                      <TableCell className="min-w-48 align-top">
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
                          {complianceLabels[resource.compliance] ?? "Unknown"}
                        </StatusBadge>
                        <p className="mt-2 whitespace-normal text-xs text-muted-foreground">
                          {resource.lastVerifiedAt
                            ? `Last checked ${formatTimestamp(resource.lastVerifiedAt).local}`
                            : "Not checked yet"}
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
                        {resource.reason ? (
                          <p className="mt-2 whitespace-normal break-words">
                            {blockedReasonLabel(resource.reason)}
                          </p>
                        ) : null}
                        {resource.disposition === ResourceDisposition.ATTENTION ? (
                          <p className="mt-2 whitespace-normal">
                            lindm won't retry automatically. Fix the cause, then assign the profile
                            again.
                          </p>
                        ) : null}
                      </TableCell>
                      <TableCell className="min-w-64 align-top">
                        <ActionHistory action={resource.latestAction} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title="Nothing managed yet"
                description="Assign a profile to manage this device's services and settings."
                action={canPermission(principal, "resources.assign") ? emptyAction : undefined}
              />
            )}
            {state.data.releases.length ? (
              <div className="grid gap-2">
                <h3 className="font-semibold">Removed items</h3>
                <p className="text-sm text-muted-foreground">
                  Items no longer in the profile. lindm only undoes changes it made itself.
                </p>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Item</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Requested</TableHead>
                      <TableHead>Completed</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {state.data.releases.map((release) => (
                      <TableRow key={release.releaseId}>
                        <TableCell className="align-top">
                          <p className="font-medium break-all">
                            {release.ref?.canonicalKey ?? "Unnamed item"}
                          </p>
                          <TechnicalDetails
                            items={[
                              { label: "Release ID", value: release.releaseId },
                              { label: "From assignment", value: release.sourceAssignmentId },
                              { label: "To assignment", value: release.supersedingAssignmentId },
                            ]}
                          />
                        </TableCell>
                        <TableCell className="align-top">
                          <StatusBadge status={release.completedAt ? "success" : "warning"}>
                            {enumLabel(release.state)}
                          </StatusBadge>
                          {release.reason ? (
                            <p className="mt-1 whitespace-normal">{release.reason}</p>
                          ) : null}
                        </TableCell>
                        <TableCell className="align-top">
                          {formatTimestamp(release.requestedAt).local}
                        </TableCell>
                        <TableCell className="align-top">
                          {release.completedAt
                            ? formatTimestamp(release.completedAt).local
                            : "Not yet"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : null}
            <div className="grid gap-2">
              <h3 className="font-semibold">Recent changes</h3>
              {state.data.recentActions.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Item</TableHead>
                      <TableHead>Profile</TableHead>
                      <TableHead>Sent</TableHead>
                      <TableHead>Result</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {state.data.recentActions.map((recent) => (
                      <TableRow
                        key={
                          recent.action?.actionId ?? `${recent.assignmentId}:${recent.resourceId}`
                        }
                      >
                        <TableCell className="align-top">
                          <p className="font-medium break-all">
                            {recent.ref?.canonicalKey ?? "Unnamed item"}
                          </p>
                          <TechnicalDetails
                            items={[
                              { label: "Action ID", value: recent.action?.actionId },
                              { label: "Assignment ID", value: recent.assignmentId },
                              {
                                label: "Sequence",
                                value: recent.action?.resourceSequence.toString(),
                              },
                            ]}
                          />
                        </TableCell>
                        <TableCell className="align-top">
                          <StatusBadge status="neutral">
                            {recent.assignmentId === assignment?.assignmentId
                              ? "Current"
                              : "Previous"}
                          </StatusBadge>
                        </TableCell>
                        <TableCell className="align-top">
                          {formatTimestamp(recent.action?.issuedAt).local}
                        </TableCell>
                        <TableCell className="align-top">
                          {recent.action?.status ? (
                            <ResourceExecutionStatus
                              state={recent.action.status.state}
                              verification={recent.action.status.verification?.disposition}
                            />
                          ) : (
                            <StatusBadge status="neutral">Waiting for device</StatusBadge>
                          )}
                          <FailureNote failure={recent.action?.status?.failure} />
                          {recent.action?.closedReason ? (
                            <p className="mt-1 text-muted-foreground">
                              {recent.action.closedAt ? "Closed" : "Cancelling"}:{" "}
                              {recent.action.closedReason}
                            </p>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <p className="border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
                  No recent changes.
                </p>
              )}
            </div>
          </>
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
    return <StatusBadge status="neutral">Removed</StatusBadge>;
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
      {state === undefined ? "Waiting for device" : enumLabel(ResourceExecutionState[state])}
    </StatusBadge>
  );
}

function FailureNote({ failure }: { failure: ResourceExecutionFailure | undefined }) {
  if (
    failure === undefined ||
    failure === ResourceExecutionFailure.UNSPECIFIED ||
    failure === ResourceExecutionFailure.NONE
  )
    return null;
  return <p className="mt-1">Problem: {enumLabel(ResourceExecutionFailure[failure])}</p>;
}

function ActionHistory({ action }: { action: ServiceActionSummary | undefined }) {
  if (!action) return <p className="text-muted-foreground">No changes sent yet.</p>;
  const status = action.status;
  const checks =
    status?.verification?.checks.case === "systemdService"
      ? status.verification.checks.value
      : undefined;
  return (
    <div className="grid gap-1 whitespace-normal text-xs">
      <ResourceExecutionStatus
        state={status?.state}
        verification={status?.verification?.disposition}
      />
      <FailureNote failure={status?.failure} />
      <p>Sent {formatTimestamp(action.issuedAt).local}</p>
      {status?.completedAt ? <p>Finished {formatTimestamp(status.completedAt).local}</p> : null}
      {action.closedReason ? (
        <p>
          {action.closedAt ? "Closed" : "Cancelling"}: {action.closedReason}
        </p>
      ) : null}
      <TechnicalDetails
        items={[
          { label: "Action ID", value: action.actionId },
          { label: "Sequence", value: action.resourceSequence.toString() },
          { label: "Issued (server)", value: formatTimestamp(action.issuedAt).local },
          { label: "Expires (server)", value: formatTimestamp(action.expiresAt).local },
          {
            label: "Start authorized (server)",
            value: formatTimestamp(action.startAuthorizedAt).local,
          },
          { label: "Started (device clock)", value: formatTimestamp(status?.startedAt).local },
          { label: "Completed (device clock)", value: formatTimestamp(status?.completedAt).local },
          { label: "Attested (device clock)", value: formatTimestamp(action.attestedAt).local },
          { label: "Received (server)", value: formatTimestamp(action.receivedAt).local },
          { label: "Evidence revision", value: action.actionRevision.toString() },
          {
            label: "Read-only check",
            value: status?.readOnly
              ? enumLabel(
                  VerificationDisposition[
                    status.verification?.disposition ?? VerificationDisposition.UNSPECIFIED
                  ],
                )
              : undefined,
          },
          {
            label: "Preparation",
            value:
              status?.state === ResourceExecutionState.PREPARING
                ? "Preparing, nothing changed yet"
                : status?.preparationOutcome
                  ? "Ended before any change"
                  : undefined,
          },
        ]}
      >
        {status ? (
          <div className="mt-2 grid gap-3">
            <Observation label="Before" observation={status.before} />
            <Observation label="After" observation={status.verification?.after} />
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
        ) : null}
      </TechnicalDetails>
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
    ? "Profile needs attention"
    : unknown
      ? "Profile status unknown"
      : stale
        ? "Profile not checked recently"
        : compliant
          ? remediated
            ? "Profile drift fixed"
            : "Profile compliant"
          : data && resources.length === 0
            ? "No profile"
            : "Profile status unknown";
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
        {pendingReleases ? "Removing profile items" : label}
      </TooltipTrigger>
      <TooltipContent>
        Based on the latest check of this device's assigned profile, not a live probe.
      </TooltipContent>
    </Tooltip>
  );
}
