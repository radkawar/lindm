import { useQuery } from "@tanstack/react-query";
import {
  ServiceResourceDisposition,
  type ServiceActionSummary,
} from "../../../gen/lindm/admin/v1/service_assignments_pb";
import {
  ServiceExecutionFailure,
  ServiceExecutionState,
} from "../../../gen/lindm/agent/v1/service_execution_pb";
import {
  ServiceEnablement,
  ServiceRuntimeState,
  type ServiceObservation,
} from "../../../gen/lindm/agent/v1/service_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { ServiceAssignmentForm } from "./assignment-form";
import { serviceStateQueryOptions } from "./queries";

function enumLabel(value: string | undefined): string {
  return value?.toLowerCase().replaceAll("_", " ") ?? "Unknown";
}

export function DeviceServices({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const state = useQuery(serviceStateQueryOptions(lifetime, deviceId));
  const failure = state.error ? toRpcFailure(state.error) : null;
  const assignment = state.data?.assignment;
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Services</h2>
        </CardTitle>
        <CardDescription>
          Results are device-signed history, not live compliance. A successful result describes a
          past execution, not the service state now. Clearing an assignment does not revert
          services.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-5">
        <Button
          className="w-fit"
          variant="outline"
          disabled={state.isFetching}
          onClick={() => void state.refetch()}
        >
          Refresh service state
        </Button>
        {state.isPending ? <p role="status">Loading service state…</p> : null}
        {failure ? (
          <Alert variant="destructive">
            <AlertTitle>
              {failure.denied ? "Not authorized to read services" : "Service state unavailable"}
            </AlertTitle>
            <AlertDescription>
              {failure.codeName}: {failure.message}
              {state.data ? " Previously loaded state below may be stale." : ""}
            </AlertDescription>
          </Alert>
        ) : null}
        {state.data ? (
          <>
            <div className="grid gap-2 text-sm">
              <h3 className="font-semibold">Current assignment</h3>
              {assignment ? (
                <>
                  <p>
                    {assignment.profileId
                      ? `${assignment.profileName} · revision ${assignment.revisionNumber.toString()}`
                      : "None — management stopped"}
                  </p>
                  <p className="break-all">
                    Assigned by {assignment.actorId} at{" "}
                    {formatTimestamp(assignment.assignedAt).local}
                  </p>
                  <p className="whitespace-pre-wrap break-words">Reason: {assignment.reason}</p>
                  <p className="break-all font-mono text-xs text-muted-foreground">
                    Assignment {assignment.assignmentId}
                  </p>
                </>
              ) : (
                <p>None — this device has never been assigned a service profile.</p>
              )}
            </div>
            {state.data.resources.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Unit</TableHead>
                    <TableHead>Desired state</TableHead>
                    <TableHead>Disposition / reason</TableHead>
                    <TableHead>Latest action (history)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {state.data.resources.map((resource) => (
                    <TableRow key={resource.resourceId}>
                      <TableCell className="align-top font-mono">
                        {resource.desired?.unit ?? "Not reported"}
                      </TableCell>
                      <TableCell className="align-top">
                        <p>
                          Runtime: {enumLabel(ServiceRuntimeState[resource.desired?.runtime ?? 0])}
                        </p>
                        <p>
                          Enablement:{" "}
                          {enumLabel(ServiceEnablement[resource.desired?.enablement ?? 0])}
                        </p>
                      </TableCell>
                      <TableCell className="align-top">
                        <Badge
                          variant={
                            resource.disposition === ServiceResourceDisposition.ATTENTION ||
                            resource.disposition === ServiceResourceDisposition.BLOCKED
                              ? "destructive"
                              : "secondary"
                          }
                        >
                          {enumLabel(ServiceResourceDisposition[resource.disposition])}
                        </Badge>
                        <p className="mt-2 whitespace-normal break-words">
                          {resource.reason || "—"}
                        </p>
                        {resource.disposition === ServiceResourceDisposition.ATTENTION ? (
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
              <p className="text-sm text-muted-foreground">
                No resources under the current assignment.
              </p>
            )}
            <div className="grid gap-2">
              <h3 className="font-semibold">Recent actions</h3>
              <p className="text-sm text-muted-foreground">
                Up to 50 recent actions, newest first, including previous assignment heads. Signed
                results are device-signed history, not live compliance. Issuance, authorization, and
                closure are server records, not proof of a native effect.
              </p>
              {state.data.recentActions.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Unit</TableHead>
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
                        <TableCell className="font-mono">{recent.unit}</TableCell>
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
                <p className="text-sm text-muted-foreground">No recent actions.</p>
              )}
            </div>
          </>
        ) : null}
        <ServiceAssignmentForm
          deviceId={deviceId}
          expectedAssignmentId={assignment?.assignmentId}
          stateReady={state.isSuccess && !failure}
        />
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
