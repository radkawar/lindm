import { create } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import {
  ControlRolloutRequest_Operation,
  ControlRolloutRequestSchema,
  type RolloutState,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import type { TargetCandidate, TargetRef } from "../../../gen/lindm/policy/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { SelectField } from "@/components/ui/select-field";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { AssignmentForm } from "./assignment";
import { ReasonControl } from "./controls";
import { TargetMutation } from "./mutation";
import {
  dynamicGroupQueryOptions,
  rolloutsQueryOptions,
  targetAssignmentsQueryOptions,
} from "./queries";
import { ListStatus, TargetPagination } from "./list";
import { TargetPreviewView } from "./preview";
import { RolloutForm } from "./rollout-form";
import { rolloutName, type TargetNames } from "./pickers";
import { formatSeconds } from "./duration";

function deviceCount(count: number) {
  return count === 1 ? "1 device" : `${count} devices`;
}

const ROLLOUT_REASON_MESSAGES: Record<string, string> = {
  failure_threshold:
    "Too many devices across the rollout reported a failure. Inspect their latest reports.",
  unavailable_threshold:
    "Too many devices across the rollout are unavailable. Check their latest contact and reports.",
  unknown_threshold:
    "Too many devices across the rollout have unverified results. Inspect their evidence.",
  rollout_authorization_denied:
    "The rollout's creator is no longer authorized to advance it. Ask an administrator to review their access.",
};

export function RolloutsView({
  initialDevice = "",
  names,
  creating,
  onCreatingChange: setCreating,
}: {
  initialDevice?: string;
  names: TargetNames;
  // The New rollout form's visibility lives in the URL, so the command palette can open it.
  creating: boolean;
  onCreatingChange: (creating: boolean) => void;
}) {
  const principal = usePrincipal();
  const canAssign = canPermission(principal, "resources.assign", true);
  const formHeading = useRef<HTMLHeadingElement>(null);
  const newRollout = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!creating) return;
    formHeading.current?.scrollIntoView({ block: "start" });
    formHeading.current?.focus();
  }, [creating]);
  const inspect = <TargetPreviewView key={initialDevice} initialDevice={initialDevice} />;
  return (
    <section className="grid min-w-0 gap-6">
      <PageHeader
        title="Rollouts"
        description="Who gets which profile version, and how far each staged rollout has progressed."
        actions={
          canAssign ? (
            <Button
              ref={newRollout}
              type="button"
              aria-controls={creating ? "new-rollout" : undefined}
              aria-expanded={creating}
              onClick={() => {
                if (!creating) setCreating(true);
                else formHeading.current?.focus();
              }}
            >
              New rollout
            </Button>
          ) : null
        }
      />
      {initialDevice ? inspect : null}
      {canAssign ? (
        <>
          <StagedRollouts names={names} />
          <SavedAssignments names={names} />
          {creating ? (
            <Card id="new-rollout" role="region" aria-labelledby="new-rollout-title">
              <CardHeader>
                <CardTitle>
                  <h2 id="new-rollout-title" ref={formHeading} tabIndex={-1}>
                    New rollout
                  </h2>
                </CardTitle>
                <CardDescription>
                  Choose a target and a profile version, then review the affected devices before
                  saving.
                </CardDescription>
                <CardAction>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setCreating(false);
                      newRollout.current?.focus();
                    }}
                  >
                    Close
                  </Button>
                </CardAction>
              </CardHeader>
              <CardContent>
                <AssignmentForm />
              </CardContent>
            </Card>
          ) : null}
        </>
      ) : (
        <p className="text-sm text-muted-foreground">
          You can inspect and activate devices you manage. Ask an administrator with full assignment
          access to change assignments or rollouts.
        </p>
      )}
      {initialDevice ? null : inspect}
    </section>
  );
}

function DynamicGroupName({ value }: { value: string }) {
  const query = useQuery(dynamicGroupQueryOptions(useAuthLifetime(), value));
  if (query.data) return query.data.name || "(unnamed)";
  if (query.isPending) return "(loading name…)";
  if (query.error) return "(name unavailable)";
  return "(deleted dynamic group)";
}

function TargetName({ target, names }: { target?: TargetRef; names: TargetNames }) {
  const value = target?.target.value ?? "";
  const DeviceName = names.deviceName;
  const GroupName = names.groupName;
  if (!value) return <>no target chosen</>;
  switch (target?.target.case) {
    case "deviceId":
      return (
        <>
          device <DeviceName value={value} />
        </>
      );
    case "dynamicGroupId":
      return (
        <>
          dynamic group <DynamicGroupName value={value} />
        </>
      );
    default:
      return (
        <>
          device group <GroupName value={value} />
        </>
      );
  }
}

// What a saved assignment delivers and to whom, in one line.
function Delivery({ candidate, names }: { candidate: TargetCandidate; names: TargetNames }) {
  const ProfileVersionName = names.profileVersionName;
  const assignment = candidate.assignment;
  if (!assignment) return null;
  return (
    <span className="break-words">
      <span className="font-medium">
        <ProfileVersionName value={assignment.profileRevisionId} />
      </span>{" "}
      to <TargetName target={assignment.target} names={names} />
    </span>
  );
}

function StagedRollouts({ names }: { names: TargetNames }) {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const [planning, setPlanning] = useState(false);
  const list = useQuery({
    ...rolloutsQueryOptions(lifetime, afterId, ""),
    refetchInterval: 10_000,
    refetchIntervalInBackground: false,
  });
  // Assignments name what each rollout delivers; the first page shares the
  // Saved assignments cache entry.
  const assignments = useQuery(targetAssignmentsQueryOptions(lifetime, ""));
  const states = list.data?.filter((state) => state.rollout) ?? [];
  const paused = states.filter((state) => state.paused).length;
  return (
    <section aria-labelledby="staged-rollouts-title" className="grid min-w-0 gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="grid gap-1">
          <h2 id="staged-rollouts-title" className="text-base font-semibold">
            Staged rollouts
          </h2>
          {list.data && !list.error ? (
            <p className="text-sm text-muted-foreground">
              {states.length - paused} in progress, {paused} paused
              {list.data.length === 100 ? " on this page" : ""}.
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Updates every 10 seconds.</span>
          <Button
            type="button"
            variant="outline"
            aria-expanded={planning}
            onClick={() => setPlanning(!planning)}
          >
            Plan staged rollout
          </Button>
        </div>
      </div>
      {planning ? (
        <Card>
          <CardHeader>
            <CardTitle>
              <h3>Plan staged rollout</h3>
            </CardTitle>
            <CardAction>
              <Button type="button" variant="outline" onClick={() => setPlanning(false)}>
                Close
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <RolloutForm />
          </CardContent>
        </Card>
      ) : null}
      <ListStatus
        pending={list.isPending}
        error={list.error}
        empty={list.data?.length === 0}
        firstPage={!afterId}
        noun="staged rollouts"
        emptyDescription="Plan a staged rollout to deliver a profile version to a small group first, then widen it when devices report healthy."
      />
      {!list.error
        ? states.map((state) => (
            <RolloutCard
              key={state.rollout?.rolloutId}
              state={state}
              names={names}
              deliveries={assignments.data?.filter(
                (candidate) => candidate.assignment?.rolloutId === state.rollout?.rolloutId,
              )}
              deliveriesComplete={!!assignments.data && assignments.data.length < 100}
            />
          ))
        : null}
      {afterId || list.data?.length === 100 ? (
        <TargetPagination
          afterId={afterId}
          nextId={list.data?.length === 100 ? list.data.at(-1)?.rollout?.rolloutId : undefined}
          busy={list.isFetching}
          onPage={setAfterId}
        />
      ) : null}
    </section>
  );
}

function SavedAssignments({ names }: { names: TargetNames }) {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const [editing, setEditing] = useState("");
  const list = useQuery(targetAssignmentsQueryOptions(lifetime, afterId));
  const rollouts = useQuery(rolloutsQueryOptions(lifetime, "", ""));
  return (
    <section aria-labelledby="saved-assignments-title" className="grid min-w-0 gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="saved-assignments-title" className="text-base font-semibold">
          Saved assignments
        </h2>
        <Button
          type="button"
          variant="outline"
          disabled={list.isFetching}
          onClick={() => void list.refetch()}
        >
          Refresh assignments
        </Button>
      </div>
      <ListStatus
        pending={list.isPending}
        error={list.error}
        empty={list.data?.length === 0}
        firstPage={!afterId}
        noun="saved assignments"
        emptyDescription="Choose New rollout to assign a profile version to a device or group."
      />
      {!list.error && list.data?.length ? (
        <ul className="grid min-w-0 gap-3">
          {list.data.map((candidate) => {
            const assignment = candidate.assignment;
            if (!assignment) return null;
            const rollout = assignment.rolloutId
              ? rollouts.data?.find((state) => state.rollout?.rolloutId === assignment.rolloutId)
              : undefined;
            const open = editing === assignment.assignmentId;
            return (
              <li key={assignment.assignmentId} className="grid min-w-0 gap-2 border p-3 text-sm">
                <Delivery candidate={candidate} names={names} />
                <div className="flex flex-wrap items-center gap-2 text-muted-foreground">
                  <StatusBadge status={assignment.disabled ? "neutral" : "info"}>
                    {assignment.disabled ? "Disabled" : "Saved, not proof of activation"}
                  </StatusBadge>
                  <span>Priority {assignment.priority}</span>
                  {assignment.rolloutId ? (
                    <span>
                      Staged rollout: {rollout ? rolloutName(rollout) : "not on the first page"}
                    </span>
                  ) : null}
                  {assignment.exclusions.length ? (
                    <span>
                      {assignment.exclusions.length}{" "}
                      {assignment.exclusions.length === 1 ? "exclusion" : "exclusions"}
                    </span>
                  ) : null}
                  {assignment.activatesAt ? (
                    <span>Eligible from {formatTimestamp(assignment.activatesAt).local}</span>
                  ) : null}
                  {assignment.expiresAt ? (
                    <span>Expires {formatTimestamp(assignment.expiresAt).local}</span>
                  ) : null}
                </div>
                <Button
                  type="button"
                  variant="outline"
                  className="w-fit"
                  aria-expanded={open}
                  onClick={() => setEditing(open ? "" : assignment.assignmentId)}
                >
                  {open ? "Close change review" : "Review a change"}
                </Button>
                {open ? (
                  <AssignmentForm
                    key={`${assignment.assignmentId}:${candidate.revision}`}
                    candidate={candidate}
                  />
                ) : null}
                <TechnicalDetails
                  items={[
                    { label: "Assignment ID", value: assignment.assignmentId },
                    { label: "Revision", value: candidate.revision.toString() },
                  ]}
                />
              </li>
            );
          })}
        </ul>
      ) : null}
      {afterId || list.data?.length === 100 ? (
        <TargetPagination
          afterId={afterId}
          nextId={
            list.data?.length === 100 ? list.data.at(-1)?.assignment?.assignmentId : undefined
          }
          busy={list.isFetching}
          onPage={setAfterId}
        />
      ) : null}
    </section>
  );
}

function RolloutCard({
  state,
  names,
  deliveries,
  deliveriesComplete,
}: {
  state: RolloutState;
  names: TargetNames;
  deliveries?: TargetCandidate[];
  deliveriesComplete: boolean;
}) {
  const rollout = state.rollout;
  if (!rollout) return null;
  const stage = rollout.rings[state.ringIndex];
  const next = rollout.rings[state.ringIndex + 1];
  // Selection counts move only when a saved assignment uses this rollout.
  const unused = !!deliveries && deliveriesComplete && deliveries.length === 0;
  return (
    <article className="grid min-w-0 gap-3 border p-4">
      <h3 className="break-words text-sm font-semibold">{rolloutName(state)}</h3>
      <p className="flex flex-wrap items-center gap-2 text-sm">
        <StatusBadge status={state.paused ? "warning" : unused ? "neutral" : "info"}>
          {state.paused
            ? "Paused"
            : unused
              ? "Not delivering yet"
              : !next
                ? "Final stage"
                : stage?.manualPromotion
                  ? "Manual promotion required"
                  : "Waiting to advance"}
        </StatusBadge>
        <span>
          Stage {state.ringIndex + 1} of {rollout.rings.length}: {stage?.name ?? "Unknown"}
        </span>
      </p>
      {deliveries?.length ? (
        <ul className="grid gap-1 text-sm">
          {deliveries.map((candidate) => (
            <li key={candidate.assignment?.assignmentId}>
              <Delivery candidate={candidate} names={names} />
            </li>
          ))}
        </ul>
      ) : deliveries ? (
        <p className="text-sm text-muted-foreground">
          {deliveriesComplete
            ? "No saved assignment uses this rollout yet. Choose it in a new rollout to stage a profile version."
            : "No saved assignment on the first page uses this rollout."}
        </p>
      ) : null}
      {state.pauseReason ? (
        <p className="break-words text-sm">
          Paused:{" "}
          {ROLLOUT_REASON_MESSAGES[state.pauseReason] ??
            "The server recorded a reason this console doesn't recognize. See Details."}
        </p>
      ) : null}
      <p className="text-sm">
        {deviceCount(state.selectedCount)} included, {state.pendingCount} waiting,{" "}
        {state.excludedCount} excluded. These are saved rollout counts, not proof of device
        execution.
      </p>
      {!state.paused && !unused && next && !stage?.manualPromotion ? (
        <p className="text-sm text-muted-foreground">
          {state.gateReason
            ? (ROLLOUT_REASON_MESSAGES[state.gateReason] ??
              "A promotion check has not passed. Review the stage's guardrails and device evidence.")
            : state.promotionReady
              ? "Health and soak checks currently pass. The server still checks the creator's access before advancing."
              : "Waiting for the soak period and required healthy observations. Review the stage's guardrails and device evidence."}{" "}
          Refreshing this page never promotes a stage.
        </p>
      ) : null}
      <details>
        <summary className="cursor-pointer text-sm font-medium">Promotion evidence</summary>
        <div className="mt-3 grid gap-2 text-sm">
          <p>
            Across all stages reached: {state.healthyCount} healthy, {state.failedCount} failed,{" "}
            {state.unknownCount} unverified and {state.unavailableCount} unavailable. Each device is
            counted once; these are not just the current stage&apos;s included devices.
          </p>
          <p>Stage started: {formatTimestamp(state.stageStartedAt).local}.</p>
          {state.nextPromotionAt ? (
            <p>
              Earliest soak completion: {formatTimestamp(state.nextPromotionAt).local}. This is not
              a promised promotion time; health and authorization must still pass.
            </p>
          ) : null}
        </div>
      </details>
      <details>
        <summary className="cursor-pointer text-sm font-medium">Stage scope and guardrails</summary>
        <ol className="mt-3 grid gap-3">
          {rollout.rings.map((ring) => (
            <li className="grid gap-2 border p-3 text-sm" key={ring.name}>
              <h4 className="font-medium">
                {ring.name}: {ring.cumulativeBasisPoints / 100}% of devices in total
              </h4>
              <p>
                Target: <TargetName target={ring.cohort} names={names} />
              </p>
              <p>
                At least {deviceCount(ring.minimumCanaries)} to start and {ring.minimumObserved}{" "}
                reporting; observe for {formatSeconds(ring.soakSeconds)}. Observations must be no
                older than {formatSeconds(ring.healthMaxAgeSeconds)}.
              </p>
              <p>
                Allow at most {ring.failureBasisPoints / 100}% failed,{" "}
                {ring.unknownBasisPoints / 100}% unknown and {ring.unavailableBasisPoints / 100}%
                unavailable devices.
              </p>
              <p>
                {ring.manualPromotion
                  ? "Administrator promotion required."
                  : "Automatic promotion allowed when guardrails pass."}
              </p>
            </li>
          ))}
        </ol>
      </details>
      <TargetMutation
        title="Save rollout decision"
        formKey={`rollout-control:${rollout.rolloutId}`}
        schema={ControlRolloutRequestSchema}
        initial={() =>
          create(ControlRolloutRequestSchema, {
            requestId: newRequestId(),
            rolloutId: rollout.rolloutId,
            expectedRevision: state.revision,
            operation: state.paused
              ? ControlRolloutRequest_Operation.RESUME
              : ControlRolloutRequest_Operation.PAUSE,
          })
        }
        send={(request, signal) => adminClient.controlRollout(request, { signal })}
        fields={(request, change, disabled) => (
          <fieldset disabled={disabled} className="grid gap-3">
            <label className="grid gap-1.5 text-sm">
              Rollout decision
              <SelectField
                aria-label="Rollout decision"
                disabled={disabled}
                value={String(request.operation)}
                options={[
                  { value: ControlRolloutRequest_Operation.PAUSE, label: "Pause this rollout" },
                  { value: ControlRolloutRequest_Operation.RESUME, label: "Resume this rollout" },
                  ...(stage?.manualPromotion && next
                    ? [
                        {
                          value: ControlRolloutRequest_Operation.PROMOTE,
                          label: `Advance to ${next.name}, if guardrails pass`,
                        },
                      ]
                    : []),
                ]}
                onValueChange={(value) => {
                  const nextOperation = Number(value);
                  if (
                    nextOperation === ControlRolloutRequest_Operation.PAUSE ||
                    nextOperation === ControlRolloutRequest_Operation.RESUME ||
                    nextOperation === ControlRolloutRequest_Operation.PROMOTE
                  ) {
                    change(
                      create(ControlRolloutRequestSchema, { ...request, operation: nextOperation }),
                    );
                  }
                }}
              />
            </label>
            <p className="text-sm">
              {request.operation === ControlRolloutRequest_Operation.PAUSE
                ? "Pause selection for this rollout; previously activated changes are not undone."
                : request.operation === ControlRolloutRequest_Operation.RESUME
                  ? "Resume selection under the saved stage guardrails; this does not activate device changes."
                  : "Advance from the reviewed stage only if its saved stage, health and soak checks still match. This does not activate device changes."}
            </p>
            <ReasonControl
              value={request.reason}
              onChange={(reason) =>
                change(create(ControlRolloutRequestSchema, { ...request, reason }))
              }
            />
          </fieldset>
        )}
      />
      <TechnicalDetails
        items={[
          { label: "Rollout ID", value: rollout.rolloutId },
          { label: "Revision", value: state.revision.toString() },
          { label: "Recorded pause reason", value: state.pauseReason },
          { label: "Current promotion check", value: state.gateReason },
        ]}
      />
    </article>
  );
}
