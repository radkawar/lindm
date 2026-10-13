import { toJsonString } from "@bufbuild/protobuf";
import {
  ResourceDesiredStateSchema,
  ResourceObservationSchema,
  VerificationDisposition,
  type ResourceObservation,
} from "../../../gen/lindm/resource/v1/resource_pb";
import { useQuery } from "@tanstack/react-query";
import { Fragment, type ReactNode } from "react";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import {
  ResourceCompliance,
  ResourceDisposition,
  type ResourceActionSummary,
  type ResourceState,
} from "../../../gen/lindm/admin/v1/assignments_pb";
import {
  ResourceExecutionFailure,
  ResourceExecutionState,
} from "../../../gen/lindm/agent/v1/resource_execution_pb";
import type { SystemdServiceObservation } from "../../../gen/lindm/resource/v1/observations_pb";
import { ResourceKind, type ResourceRef } from "../../../gen/lindm/resource/v1/identity_pb";
import type { DeviceCapabilityState } from "../../../gen/lindm/admin/v1/capabilities_pb";
import { BlockedReason } from "@/components/ui/blocked-reason";
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
import { blockedReasonCopy, blockedReasonLabel, toRpcFailure } from "@/lib/errors";
import { settingTechnicalIds, settingTitle } from "@/lib/setting-identity";
import {
  applicabilityFeatures,
  applicabilityPlatforms,
  resourceKindLabel,
} from "@/lib/resource-labels";
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

// Server release states (resource_releases.state). Only "pending" is still in
// progress; the others are final until the item is assigned again.
const releaseStateLabels: Record<string, string> = {
  pending: "Removing",
  released: "Removed",
  release_conflict: "Not removed",
  baseline_unknown: "Not removed",
};

const releaseReasonLabels: Record<string, string> = {
  native_unsupported: "The device cannot remove this item type. It kept the item.",
  precondition_failed: "The item changed since lindm set it. The device kept the item.",
  native_tool_path_unprotected:
    "The system tool lacks protection on this device. lindm did not run it. Nothing changed.",
  native_package_manager_busy:
    "Another package manager was running on the device. Nothing changed; assign the profile again to retry.",
  outcome_unknown: "The removal outcome is unknown. Check the item on the device.",
  release_failed: "The device couldn't remove this item. Check it on the device.",
  resource_reassigned: "The new profile manages this item too, so it stays.",
  cancelled_no_effect: "The device cancelled removal before making changes.",
  adoption_approval_required:
    "lindm took over this existing item without recorded approval. The device kept the item.",
  ownership_baseline_unavailable:
    "lindm has no record of this item before takeover. The device kept the item.",
  resource_executor_not_available:
    "The agent cannot manage this item type. The device kept the item.",
  resource_capability_evidence_unavailable:
    "The device has not reported support for this item. It kept the item.",
  resource_verification_not_available: "The device cannot verify this item type. It kept the item.",
};

// Rows lindm never sends get one state instead of check, result and change
// columns that would all restate "nothing happened".
const SINGLE_STATE_LABELS: Partial<Record<ResourceDisposition, string>> = {
  [ResourceDisposition.UNSUPPORTED]: "Device cannot apply",
  [ResourceDisposition.NOT_APPLICABLE]: "Not applicable to this device",
  [ResourceDisposition.WAITING_FOR_DEVICE_FACTS]: "Waiting for device facts",
};

function singleStateSentence(resource: ResourceState): string {
  if (
    resource.disposition === ResourceDisposition.NOT_APPLICABLE &&
    resource.applicability?.products.length
  ) {
    return "This item targets other platforms. lindm does not send it to this device or count it for compliance.";
  }
  const features = applicabilityFeatures(resource.applicability);
  if (resource.reason === "resource_feature_evidence_unavailable" && features) {
    return `This item requires ${features}. No device reports this capability yet. lindm does not send the item. Remove the requirement from the profile.`;
  }
  return blockedReasonLabel(resource.reason);
}

export function DeviceResources({
  deviceId,
  lastContact,
  capabilities,
  emptyAction,
}: {
  deviceId: string;
  // The device's last check-in, to explain items it has not picked up yet.
  lastContact?: Timestamp;
  // Granted and reported capabilities, so a blocked item names the real remedy.
  capabilities?: DeviceCapabilityState;
  emptyAction?: ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const state = useQuery(resourceStateQueryOptions(lifetime, deviceId));
  const failure = state.error ? toRpcFailure(state.error) : null;
  const assignment = state.data?.assignment;
  const actor = !assignment?.actorId.trim()
    ? "the system"
    : assignment.actorId === principal.id
      ? "you"
      : assignment.actorDisplayName || "a former administrator";
  // Work is minted only when the device asks for it, so a pending item with no
  // action means the device has not picked it up yet.
  const unpicked =
    (state.data?.resources.filter(
      (resource) => !resource.latestAction && resource.disposition === ResourceDisposition.PENDING,
    ).length ?? 0) +
    (state.data?.releases.filter((release) => release.state === "pending").length ?? 0);
  // A managed item's name, using its desired state when this device still has it
  // (a firewall zone is described by what it binds, never by its UUID).
  const itemTitle = (ref: ResourceRef | undefined) =>
    settingTitle(
      ref,
      state.data?.resources.find(
        (resource) =>
          resource.desired?.ref?.kind === ref?.kind &&
          resource.desired?.ref?.canonicalKey === ref?.canonicalKey,
      )?.desired,
    ) ?? "Unnamed item";
  // The same name for display: a unit, path, package or kernel key is a technical
  // value and reads as code (design.md); a firewall zone is described in words.
  const itemName = (ref: ResourceRef | undefined, title = itemTitle(ref)) =>
    ref?.kind === ResourceKind.FIREWALL_ZONE || !settingTitle(ref) ? (
      title
    ) : (
      <code className="font-mono text-[0.92em]">{title}</code>
    );
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
            {state.data ? <p>These results precede the failed refresh.</p> : null}
          </RpcError>
        ) : null}
        {state.data ? (
          <>
            <div className="grid gap-2 border bg-muted/30 p-4 text-sm">
              <h3 className="font-semibold">Assigned profile</h3>
              {assignment?.profileId ? (
                <>
                  <p>
                    {assignment.profileName}, version {assignment.revisionNumber.toString()}
                  </p>
                  <p className="break-words text-muted-foreground">
                    Assigned by {actor} on {formatTimestamp(assignment.assignedAt).local}. Checked{" "}
                    {checkInterval(assignment.reconcileIntervalSeconds)}.
                  </p>
                  <p className="whitespace-pre-wrap break-words text-muted-foreground">
                    Reason: {assignment.reason}
                  </p>
                </>
              ) : assignment?.sources.length ? (
                <>
                  <p className="break-words">
                    From rollouts:{" "}
                    {assignment.sources
                      .map(
                        (source) =>
                          `${source.profileName || "Unnamed profile"}, version ${source.revisionNumber.toString()}`,
                      )
                      .join("; ")}
                  </p>
                  <p className="break-words text-muted-foreground">
                    Applied by {actor} on {formatTimestamp(assignment.assignedAt).local}. Checked{" "}
                    {checkInterval(assignment.reconcileIntervalSeconds)}.
                  </p>
                  {assignment.reason && assignment.reason !== "target_preview_activation" ? (
                    <p className="whitespace-pre-wrap break-words text-muted-foreground">
                      Reason: {assignment.reason}
                    </p>
                  ) : null}
                </>
              ) : assignment ? (
                <>
                  <p>No profile. An administrator removed the assignment.</p>
                  <p className="whitespace-pre-wrap break-words text-muted-foreground">
                    Removed by {actor} on {formatTimestamp(assignment.assignedAt).local}. Reason:{" "}
                    {assignment.reason}
                  </p>
                </>
              ) : (
                <p>No profile assigned.</p>
              )}
              {unpicked ? (
                <p role="status" data-testid="resources-waiting-for-device">
                  Waiting for the device to pick up {unpicked} {unpicked === 1 ? "item" : "items"}.{" "}
                  {lastContact
                    ? `It last checked in ${formatTimestamp(lastContact).local}.`
                    : "It has not checked in yet."}
                </p>
              ) : null}
              <TechnicalDetails
                items={[
                  { label: "Assignment ID", value: assignment?.assignmentId },
                  { label: "Actor ID", value: assignment?.actorId },
                ]}
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
                          {itemName(
                            resource.desired?.ref,
                            (resource.desired?.state.case === "nativePackage"
                              ? resource.desired.state.value.package?.nativeName
                              : undefined) ?? itemTitle(resource.desired?.ref),
                          )}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {resourceKindLabel(resource.desired?.ref?.kind)}
                        </p>
                        {resource.dependsOn.length ? (
                          <p className="mt-1 whitespace-normal text-xs text-muted-foreground">
                            Depends on{" "}
                            {resource.dependsOn.map((dependency, index) => (
                              <Fragment key={index}>
                                {index ? ", " : ""}
                                {itemName(dependency.ref)}
                              </Fragment>
                            ))}
                          </p>
                        ) : null}
                        {resource.applicability?.products.length ||
                        resource.desired ||
                        resource.reason ||
                        (resource.latestAction && !SINGLE_STATE_LABELS[resource.disposition]) ? (
                          // One Details per row: the item's identifiers and desired
                          // state, then the latest change's exact evidence.
                          <TechnicalDetails
                            items={[
                              ...settingTechnicalIds(resource.desired?.ref),
                              { label: "Reason code", value: resource.reason },
                              {
                                label: "Target platforms",
                                value: applicabilityPlatforms(resource.applicability),
                              },
                            ]}
                          >
                            {resource.desired ? (
                              <pre className="mt-2 max-w-lg overflow-auto whitespace-pre-wrap break-all">
                                {toJsonString(ResourceDesiredStateSchema, resource.desired, {
                                  prettySpaces: 2,
                                })}
                              </pre>
                            ) : null}
                            {resource.latestAction && !SINGLE_STATE_LABELS[resource.disposition] ? (
                              <LatestChangeEvidence action={resource.latestAction} />
                            ) : null}
                          </TechnicalDetails>
                        ) : null}
                      </TableCell>
                      {SINGLE_STATE_LABELS[resource.disposition] ? (
                        <TableCell colSpan={3} className="align-top whitespace-normal">
                          <StatusBadge
                            status={
                              resource.disposition === ResourceDisposition.UNSUPPORTED
                                ? "warning"
                                : "neutral"
                            }
                          >
                            {SINGLE_STATE_LABELS[resource.disposition]}
                          </StatusBadge>
                          <p className="mt-2 max-w-prose">{singleStateSentence(resource)}</p>
                        </TableCell>
                      ) : (
                        <>
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
                              <BlockedReason
                                className="mt-2"
                                copy={blockedReasonCopy(resource.reason, capabilities)}
                              />
                            ) : null}
                            {resource.disposition === ResourceDisposition.ATTENTION ? (
                              <p className="mt-2 whitespace-normal">
                                lindm won't retry automatically. Fix the cause, then assign the
                                profile again.
                              </p>
                            ) : null}
                          </TableCell>
                          <TableCell className="min-w-64 align-top">
                            <ActionHistory
                              action={resource.latestAction}
                              resultShown={resource.disposition === ResourceDisposition.SUCCEEDED}
                            />
                          </TableCell>
                        </>
                      )}
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
                          <p className="font-medium break-all">{itemName(release.ref)}</p>
                          <TechnicalDetails
                            items={[
                              { label: "Release ID", value: release.releaseId },
                              ...settingTechnicalIds(release.ref),
                              { label: "From assignment", value: release.sourceAssignmentId },
                              { label: "To assignment", value: release.supersedingAssignmentId },
                              { label: "Reason code", value: release.reason },
                            ]}
                          />
                        </TableCell>
                        <TableCell className="align-top">
                          <StatusBadge
                            status={
                              release.state === "released"
                                ? "success"
                                : release.state === "pending"
                                  ? "info"
                                  : "warning"
                            }
                          >
                            {releaseStateLabels[release.state] ?? "Not removed"}
                          </StatusBadge>
                          {release.reason ? (
                            <p className="mt-1 whitespace-normal">
                              {releaseReasonLabels[release.reason] ??
                                blockedReasonLabel(release.reason)}
                            </p>
                          ) : null}
                        </TableCell>
                        <TableCell className="align-top">
                          {formatTimestamp(release.requestedAt).local}
                        </TableCell>
                        <TableCell className="align-top">
                          {release.completedAt
                            ? formatTimestamp(release.completedAt).local
                            : release.state === "pending"
                              ? "Not yet"
                              : "Stopped"}
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
                          <p className="font-medium break-all">{itemName(recent.ref)}</p>
                          <TechnicalDetails
                            items={[
                              { label: "Action ID", value: recent.action?.actionId },
                              ...settingTechnicalIds(recent.ref),
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
                          {recent.action?.closedReason &&
                          recent.action.closedReason !== "result" ? (
                            <p className="mt-1 text-muted-foreground">
                              {recent.action.closedAt ? "" : "Cancelling: "}
                              {blockedReasonLabel(recent.action.closedReason)}
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

// "daily", "hourly", "every 15 minutes": how often the device re-checks items.
function checkInterval(seconds: number) {
  const minutes = Math.round(seconds / 60);
  if (minutes > 0 && minutes % 1440 === 0)
    return minutes === 1440 ? "daily" : `every ${minutes / 1440} days`;
  if (minutes > 0 && minutes % 60 === 0)
    return minutes === 60 ? "hourly" : `every ${minutes / 60} hours`;
  return `every ${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
}

// The Latest change column: what happened, in words. Its exact evidence is in
// the row's one Details disclosure (LatestChangeEvidence).
function ActionHistory({
  action,
  resultShown = false,
}: {
  action: ResourceActionSummary | undefined;
  // The Result column already says the item succeeded; don't badge it twice.
  resultShown?: boolean;
}) {
  if (!action) return <p className="text-muted-foreground">No changes sent yet.</p>;
  const status = action.status;
  const repeated =
    resultShown &&
    status?.state === ResourceExecutionState.SUCCEEDED &&
    status.verification?.disposition !== VerificationDisposition.NOT_APPLICABLE;
  return (
    <div className="grid gap-1 whitespace-normal text-xs">
      {repeated ? null : (
        <ResourceExecutionStatus
          state={status?.state}
          verification={status?.verification?.disposition}
        />
      )}
      <FailureNote failure={status?.failure} />
      <p>Sent {formatTimestamp(action.issuedAt).local}</p>
      {status?.completedAt ? <p>Finished {formatTimestamp(status.completedAt).local}</p> : null}
      {action.closedReason && action.closedReason !== "result" ? (
        <p>
          {action.closedAt ? "" : "Cancelling: "}
          {blockedReasonLabel(action.closedReason)}
        </p>
      ) : null}
    </div>
  );
}

function LatestChangeEvidence({ action }: { action: ResourceActionSummary }) {
  const status = action.status;
  const checks =
    status?.verification?.checks.case === "systemdService"
      ? status.verification.checks.value
      : undefined;
  const items = [
    { label: "Action ID", value: action.actionId },
    { label: "Closed reason code", value: action.closedReason },
    { label: "Sequence", value: action.resourceSequence.toString() },
    { label: "Issued (server)", value: formatTimestamp(action.issuedAt).local },
    { label: "Expires (server)", value: formatTimestamp(action.expiresAt).local },
    { label: "Start authorized (server)", value: formatTimestamp(action.startAuthorizedAt).local },
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
  ].filter((item) => item.value);
  return (
    <div className="mt-3 grid max-w-lg gap-2 whitespace-normal">
      <p className="font-medium">Latest change</p>
      <dl className="grid gap-1 break-all">
        {items.map((item) => (
          <div key={item.label}>
            <dt className="inline font-medium">{item.label}: </dt>
            <dd className="inline font-mono">{item.value}</dd>
          </div>
        ))}
      </dl>
      {status ? (
        <div className="grid gap-3">
          <Observation label="Before" observation={status.before} />
          <Observation label="After" observation={status.verification?.after} />
          {status.verification ? (
            <div>
              <p>
                Verification: {enumLabel(VerificationDisposition[status.verification.disposition])}
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
          <p className="break-all">Resource: {settingTitle(observation.ref) ?? "Not reported"}</p>
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
  // Items outside this device's platform are neither for nor against it.
  const resources = (data?.resources ?? []).filter(
    (resource) => resource.compliance !== ResourceCompliance.NOT_APPLICABLE,
  );
  const pendingReleases = data?.releases.some((release) => release.state === "pending") ?? false;
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
            ? data.resources.length
              ? "No profile items apply to this device"
              : "No profile"
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
