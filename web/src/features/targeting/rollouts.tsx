import { create } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  ControlRolloutRequest_Operation,
  ControlRolloutRequestSchema,
  type RolloutState,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { CohortControl, ReasonControl } from "./controls";
import { TargetMutation } from "./mutation";
import { rolloutsQueryOptions, targetAssignmentsQueryOptions } from "./queries";
import { ListStatus, TargetPagination } from "./list";
import { TargetPreviewView } from "./preview";
import { RolloutForm } from "./rollout-form";
import { useTargetPickers } from "./pickers";

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

export function RolloutsView({ initialDevice = "" }: { initialDevice?: string }) {
  const principal = usePrincipal();
  const [stagedOpen, setStagedOpen] = useState(false);
  return (
    <section className="grid min-w-0 gap-6">
      <PageHeader
        title="Rollouts"
        description="Review who would receive a baseline before saving an assignment."
      />
      {canPermission(principal, "resources.assign", true) ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>
                <h2>Assign a baseline</h2>
              </CardTitle>
              <CardDescription>
                Choose a cohort and a saved baseline revision. Review the affected devices before
                committing.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <AssignmentForm />
            </CardContent>
          </Card>
          <details className="border p-4">
            <summary className="cursor-pointer text-base font-semibold">Saved assignments</summary>
            <div className="mt-4">
              <Assignments />
            </div>
          </details>
        </>
      ) : (
        <p className="text-sm text-muted-foreground">
          You can inspect and activate devices you manage. Ask an administrator with full assignment
          access to change assignments or rollouts.
        </p>
      )}
      <details className="border p-4" open={initialDevice ? true : undefined}>
        <summary className="cursor-pointer text-base font-semibold">
          Inspect and activate one device
        </summary>
        <div className="mt-4">
          <TargetPreviewView key={initialDevice} initialDevice={initialDevice} />
        </div>
      </details>
      {canPermission(principal, "resources.assign", true) ? (
        <details
          className="border p-4"
          onToggle={(event) => setStagedOpen(event.currentTarget.open)}
        >
          <summary className="cursor-pointer text-base font-semibold">Staged rollouts</summary>
          <div className="mt-4">
            <Rollouts active={stagedOpen} />
          </div>
        </details>
      ) : null}
    </section>
  );
}

function Assignments() {
  const lifetime = useAuthLifetime();
  const { profileRevisionPicker: ProfileRevisionPicker } = useTargetPickers();
  const [afterId, setAfterId] = useState("");
  const list = useQuery(targetAssignmentsQueryOptions(lifetime, afterId));
  return (
    <div className="grid min-w-0 gap-4">
      <Button
        type="button"
        className="w-fit"
        variant="outline"
        disabled={list.isFetching}
        onClick={() => void list.refetch()}
      >
        Refresh assignments
      </Button>
      <ListStatus
        pending={list.isPending}
        error={list.error}
        empty={list.data?.length === 0}
        noun="assignments"
      />
      {!list.error
        ? list.data?.map((candidate) =>
            candidate.assignment ? (
              <article
                key={candidate.assignment.assignmentId}
                className="grid min-w-0 gap-3 border p-4"
              >
                <div className="flex flex-wrap gap-2 text-sm">
                  <StatusBadge status={candidate.assignment.disabled ? "neutral" : "info"}>
                    {candidate.assignment.disabled ? "Disabled" : "Saved, not proof of activation"}
                  </StatusBadge>
                  <span>Priority {candidate.assignment.priority}</span>
                </div>
                <ProfileRevisionPicker
                  label="Assigned baseline revision"
                  value={candidate.assignment.profileRevisionId}
                  disabled
                  onChange={() => {}}
                />
                <CohortControl
                  label="Assigned cohort"
                  value={candidate.assignment.target}
                  disabled
                  onChange={() => {}}
                />
                <details>
                  <summary className="cursor-pointer text-sm font-medium">
                    Review a change to this assignment
                  </summary>
                  <div className="mt-4">
                    <AssignmentForm
                      key={`${candidate.assignment.assignmentId}:${candidate.revision}`}
                      candidate={candidate}
                    />
                  </div>
                </details>
                <TechnicalDetails
                  items={[
                    { label: "Assignment ID", value: candidate.assignment.assignmentId },
                    { label: "Revision", value: candidate.revision.toString() },
                  ]}
                />
              </article>
            ) : null,
          )
        : null}
      <TargetPagination
        afterId={afterId}
        nextId={list.data?.length === 100 ? list.data.at(-1)?.assignment?.assignmentId : undefined}
        busy={list.isFetching}
        onPage={setAfterId}
      />
    </div>
  );
}

function Rollouts({ active }: { active: boolean }) {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const list = useQuery({
    ...rolloutsQueryOptions(lifetime, afterId),
    refetchInterval: active ? 10_000 : false,
    refetchIntervalInBackground: false,
  });
  return (
    <div className="grid min-w-0 gap-4">
      <details>
        <summary className="cursor-pointer text-sm font-medium">Plan a staged rollout</summary>
        <div className="mt-4">
          <RolloutForm />
        </div>
      </details>
      <Button
        type="button"
        className="w-fit"
        variant="outline"
        disabled={list.isFetching}
        onClick={() => void list.refetch()}
      >
        Refresh rollouts
      </Button>
      <ListStatus
        pending={list.isPending}
        error={list.error}
        empty={list.data?.length === 0}
        noun="rollouts"
      />
      {!list.error
        ? list.data?.map((state) =>
            state.rollout ? <RolloutCard key={state.rollout.rolloutId} state={state} /> : null,
          )
        : null}
      <TargetPagination
        afterId={afterId}
        nextId={list.data?.length === 100 ? list.data.at(-1)?.rollout?.rolloutId : undefined}
        busy={list.isFetching}
        onPage={setAfterId}
      />
    </div>
  );
}

function RolloutCard({ state }: { state: RolloutState }) {
  const rollout = state.rollout;
  if (!rollout) return null;
  const stage = rollout.rings[state.ringIndex];
  const next = rollout.rings[state.ringIndex + 1];
  return (
    <article className="grid min-w-0 gap-3 border p-4">
      <h3 className="break-words text-sm font-semibold">
        {rollout.rings.map((ring) => ring.name).join(", ") || "Unnamed rollout"}
      </h3>
      <p className="flex flex-wrap gap-2 text-sm">
        <StatusBadge status={state.paused ? "warning" : "info"}>
          {state.paused
            ? "Paused"
            : !next
              ? "Final stage"
              : stage?.manualPromotion
                ? "Manual promotion required"
                : "Waiting to advance"}
        </StatusBadge>
        <span>Current stage: {stage?.name ?? "Unknown"}</span>
      </p>
      {state.pauseReason ? (
        <p className="break-words text-sm">
          Paused: {ROLLOUT_REASON_MESSAGES[state.pauseReason] ?? state.pauseReason}
        </p>
      ) : null}
      <p className="text-sm">
        Included: {state.selectedCount}; waiting: {state.pendingCount}; excluded:{" "}
        {state.excludedCount}. These are saved rollout counts, not proof of device execution.
      </p>
      {!state.paused && next && !stage?.manualPromotion ? (
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
                {ring.name}: {ring.cumulativeBasisPoints / 100}% cumulative share
              </h4>
              <CohortControl
                label="Stage cohort"
                value={ring.cohort}
                disabled
                onChange={() => {}}
              />
              <p>
                At least {ring.minimumCanaries} initial devices and {ring.minimumObserved}{" "}
                observations; observe for {ring.soakSeconds} seconds. Observations must be no older
                than {ring.healthMaxAgeSeconds} seconds.
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
                  : "Advance from the reviewed stage only if its saved revision, health and soak checks still match. This does not activate device changes."}
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
