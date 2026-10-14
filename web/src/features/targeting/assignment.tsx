// SPDX-License-Identifier: Apache-2.0

import { create, createRegistry } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { createValidator } from "@bufbuild/protovalidate";
import { useMutation, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import {
  PreviewTargetAssignmentImpactRequestSchema,
  RolloutStatus,
  StartRolloutRequestSchema,
  type PreviewTargetAssignmentImpactRequest,
  type PreviewTargetAssignmentImpactResponse,
  type RolloutState,
  type StartRolloutRequest,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import {
  RolloutSpecSchema,
  TargetAssignmentSchema,
  TargetRefSchema,
  type TargetCandidate,
} from "../../../gen/lindm/policy/v1/targeting_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { describeViolations } from "@/lib/validation";
import { NumberControl, ReasonControl, TargetControl, TimeControl } from "./controls";
import { AssignmentImpact } from "./impact";
import { useTargetLabel, useTargetPickers } from "./pickers";
import {
  initialStagePlan,
  planProblem,
  planRings,
  StagesEditor,
  type StagePlan,
} from "./rollout-form";

const validator = createValidator({ registry: createRegistry(audit_reason) });

// One StartRollout request and, when approval is required, its single approval
// request. Ambiguous outcomes retry this exact request; nothing creates another.
type Phase =
  | "starting"
  | "start-ambiguous"
  | "start-rejected"
  | "requesting"
  | "request-failed"
  | "awaiting"
  | "started";
type Attempt = {
  request: StartRolloutRequest;
  review: PreviewTargetAssignmentImpactResponse;
  phase: Phase;
  rollout?: RolloutState;
  approvalId?: string;
  failure?: RpcFailure;
};
const attempts = new Map<string, Attempt>();
const listeners = new Set<() => void>();
function update(key: string, next?: Attempt) {
  if (next) attempts.set(key, next);
  else attempts.delete(key);
  for (const listener of listeners) listener();
}
function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
subscribeAuthLifetime(() => {
  attempts.clear();
  for (const listener of listeners) listener();
});

function current(key: string, lifetime: AuthLifetime) {
  if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return undefined;
  return attempts.get(key);
}

async function requestApproval(key: string, lifetime: AuthLifetime, client: QueryClient) {
  const attempt = current(key, lifetime);
  if (!attempt) return;
  update(key, { ...attempt, phase: "requesting", failure: undefined });
  try {
    const response = await adminClient.createApproval(
      { lifetimeSeconds: 3600, payload: { case: "startRollout", value: attempt.request } },
      { signal: lifetime.signal },
    );
    lifetime.signal.throwIfAborted();
    if (!response.approval?.id) throw new Error("The server didn't confirm the approval request.");
    const latest = current(key, lifetime);
    if (latest) update(key, { ...latest, phase: "awaiting", approvalId: response.approval.id });
    void client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    void client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
  } catch (cause) {
    const latest = current(key, lifetime);
    if (latest) update(key, { ...latest, phase: "request-failed", failure: toRpcFailure(cause) });
  }
}

async function startRollout(key: string, lifetime: AuthLifetime, client: QueryClient) {
  const attempt = current(key, lifetime);
  if (!attempt) return;
  update(key, { ...attempt, phase: "starting", failure: undefined });
  try {
    const response = await adminClient.startRollout(attempt.request, { signal: lifetime.signal });
    lifetime.signal.throwIfAborted();
    const rollout = response.rollout;
    const latest = current(key, lifetime);
    if (!latest) return;
    void client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
    if (rollout?.status !== RolloutStatus.AWAITING_APPROVAL) {
      update(key, { ...latest, phase: "started", rollout });
      return;
    }
    if (rollout.approvalId) {
      update(key, { ...latest, phase: "awaiting", rollout, approvalId: rollout.approvalId });
      return;
    }
    update(key, { ...latest, rollout });
    await requestApproval(key, lifetime, client);
  } catch (cause) {
    const latest = current(key, lifetime);
    const failure = toRpcFailure(cause);
    if (latest)
      update(key, {
        ...latest,
        phase: failure.ambiguous ? "start-ambiguous" : "start-rejected",
        failure,
      });
  }
}

const startRefusals: Record<string, string> = {
  targeting_impact_stale:
    "Devices or settings changed after your review. Review impact again. Start the rollout.",
  targeting_not_ready:
    "No active device would change. The server saved nothing. Check the target and version.",
  invalid_targeting_request:
    "The server refused this rollout plan. Check the stages and target. Review impact again.",
};

function freshAssignment(candidate?: TargetCandidate) {
  return create(
    TargetAssignmentSchema,
    candidate?.assignment
      ? { ...candidate.assignment, rolloutId: undefined }
      : { assignmentId: newRequestId(), target: create(TargetRefSchema) },
  );
}

// The whole "Roll out" job: what and where, stages and name, the reviewed
// impact, then one reasoned request. Nothing changes before Roll out, and
// nothing changes before another administrator approves when approval is needed.
export function RolloutFlow({
  candidate,
  onClose,
}: {
  candidate?: TargetCandidate;
  onClose: () => void;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const { profileRevisionPicker: ProfileRevisionPicker } = useTargetPickers();
  const key = candidate?.assignment?.assignmentId ?? "new";
  const attempt = useSyncExternalStore(subscribe, () => attempts.get(key));
  const [draft, setDraft] = useState(() => freshAssignment(candidate));
  const [plan, setPlan] = useState<StagePlan>(initialStagePlan);
  const [name, setName] = useState<string>();
  const [review, setReview] = useState<PreviewTargetAssignmentImpactResponse>();
  const [pageAfter, setPageAfter] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [readFailure, setReadFailure] = useState<RpcFailure>();
  const [now, setNow] = useState(Date.now);
  const impact = useRef<HTMLDivElement>(null);
  // A prefilled change shows the options it already carries.
  const [moreOptions, setMoreOptions] = useState(
    () =>
      !!candidate?.assignment &&
      (candidate.assignment.priority !== 0 ||
        candidate.assignment.exclusions.length > 0 ||
        !!candidate.assignment.activatesAt ||
        !!candidate.assignment.expiresAt),
  );
  const rejected = attempt?.phase === "start-rejected";
  const frozen = !!attempt && !rejected;
  const assignment = frozen ? (attempt.request.assignment ?? draft) : draft;
  const evidence = frozen ? attempt.review : review;
  const expectedRevision = candidate?.revision ?? 0n;
  // The reviewed impact names the version (the picker lookup would fan out over
  // every profile's history); the default name appears once the review does.
  const version = evidence?.revisionLabels.find(
    (label) => label.revisionId === assignment.profileRevisionId,
  );
  const target = useTargetLabel(assignment.target);
  const defaultName =
    version && target.ready
      ? `${version.profileName} v${version.revisionNumber.toString()} to ${target.text}`.slice(
          0,
          128,
        )
      : "";
  const rolloutName = frozen ? (attempt.request.rollout?.name ?? "") : (name ?? defaultName);
  const expired =
    !!evidence && (!evidence.validUntil || timestampDate(evidence.validUntil).getTime() <= now);
  const problem = planProblem(plan);
  useEffect(() => {
    if (!evidence) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [evidence]);
  const read = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: PreviewTargetAssignmentImpactRequest) => {
      const result = await adminClient.previewTargetAssignmentImpact(request, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      if (!result.previewId || !result.assignment || result.reviewSha256.length !== 32)
        throw new Error("The impact review was incomplete. Review again.");
      return result;
    },
    onSuccess: (result, request) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      setReview(result);
      // Bring the reviewed consequences into view and focus, where the decision is.
      requestAnimationFrame(() => {
        impact.current?.scrollIntoView({ block: "start" });
        impact.current?.focus({ preventScroll: true });
      });
      setReadFailure(undefined);
      setNow(Date.now());
      setPageAfter(request.afterDeviceId ?? "");
    },
    onError: (cause) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      setReadFailure(toRpcFailure(cause));
    },
  });
  function change(next: typeof draft) {
    setDraft(next);
    setReview(undefined);
    setReadFailure(undefined);
    setError("");
    if (rejected) update(key);
  }
  function loadPage(afterDeviceId?: string) {
    if (frozen || read.isPending) return;
    if (!draft.profileRevisionId || !draft.target?.target.value) {
      setError("Choose a profile version and a target first.");
      return;
    }
    const request = create(PreviewTargetAssignmentImpactRequestSchema, {
      assignment: draft,
      expectedRevision,
      pageSize: 20,
      previewId: afterDeviceId !== undefined ? review?.previewId : undefined,
      afterDeviceId: afterDeviceId || undefined,
    });
    const result = validator.validate(PreviewTargetAssignmentImpactRequestSchema, request);
    if (result.kind !== "valid") {
      setError(
        result.kind === "invalid" ? describeViolations(result.violations) : result.error.message,
      );
      return;
    }
    if (afterDeviceId === undefined) {
      setReview(undefined);
      setPageAfter("");
    }
    if (rejected) update(key);
    setReadFailure(undefined);
    setError("");
    read.mutate(request);
  }
  function rollOut() {
    if (attempt && attempt.phase === "start-ambiguous") {
      void startRollout(key, lifetime, client);
      return;
    }
    if (attempt && attempt.phase === "request-failed") {
      void requestApproval(key, lifetime, client);
      return;
    }
    if (frozen || !review || !review.complete || expired || read.isPending || readFailure) return;
    if (problem) {
      setError(problem);
      return;
    }
    const request = create(StartRolloutRequestSchema, {
      requestId: newRequestId(),
      previewId: review.previewId,
      reviewSha256: review.reviewSha256,
      assignment: review.assignment,
      expectedRevision: review.expectedRevision,
      rollout: create(RolloutSpecSchema, {
        rolloutId: newRequestId(),
        salt: crypto.getRandomValues(new Uint8Array(32)),
        name: rolloutName.trim(),
        rings: planRings(plan, review.assignment?.target),
      }),
      reason: reason.trim(),
    });
    const result = validator.validate(StartRolloutRequestSchema, request);
    if (result.kind !== "valid") {
      setError(
        result.kind === "invalid" ? describeViolations(result.violations) : result.error.message,
      );
      return;
    }
    setError("");
    update(key, { request, review, phase: "starting" });
    void startRollout(key, lifetime, client);
  }
  const approvalRequired = evidence?.approvalRequired ?? false;
  const busy = attempt?.phase === "starting" || attempt?.phase === "requesting";
  const settled = attempt?.phase === "awaiting" || attempt?.phase === "started";
  return (
    <div
      className="grid min-w-0 gap-5"
      data-review-state={
        attempt?.phase ??
        (read.isPending
          ? "loading"
          : readFailure
            ? "error"
            : expired
              ? "stale"
              : review
                ? "reviewed"
                : "draft")
      }
    >
      <form
        className="grid min-w-0 gap-5"
        aria-label="Rollout plan"
        onSubmit={(event) => {
          event.preventDefault();
          loadPage();
        }}
      >
        <fieldset disabled={frozen || read.isPending} className="grid min-w-0 gap-4">
          <div className="grid min-w-0 gap-4 sm:grid-cols-2">
            <ProfileRevisionPicker
              label="Version"
              value={assignment.profileRevisionId}
              disabled={frozen || read.isPending}
              onChange={(profileRevisionId) =>
                change(create(TargetAssignmentSchema, { ...draft, profileRevisionId }))
              }
            />
            <TargetControl
              label="Target"
              value={assignment.target}
              disabled={frozen || read.isPending}
              onChange={(next) =>
                change(create(TargetAssignmentSchema, { ...draft, target: next }))
              }
            />
          </div>
          <StagesEditor plan={plan} onChange={setPlan} disabled={frozen} />
          <label className="grid gap-1.5 text-sm">
            Rollout name
            <Input
              data-freeform="rollout name"
              maxLength={128}
              value={rolloutName}
              placeholder="Profile version to target"
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          {/* A toggle, not a disclosure: the reviewed impact keeps the dialog's one disclosure. */}
          <Button
            type="button"
            variant="ghost"
            className="w-fit px-0"
            aria-expanded={moreOptions}
            aria-controls="rollout-more-options"
            onClick={() => setMoreOptions(!moreOptions)}
          >
            {moreOptions
              ? "Hide priority, exclusions and timing"
              : "Priority, exclusions and timing"}
          </Button>
          <div id="rollout-more-options" hidden={!moreOptions} className="grid min-w-0 gap-4">
            <NumberControl
              label="Priority"
              value={assignment.priority}
              onChange={(priority) =>
                change(create(TargetAssignmentSchema, { ...draft, priority }))
              }
            />
            <p className="text-sm text-muted-foreground">
              Where two assignments manage the same setting, the higher priority wins.
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              <TimeControl
                label="Starts applying at (local time, optional)"
                value={assignment.activatesAt}
                onChange={(activatesAt) =>
                  change(create(TargetAssignmentSchema, { ...draft, activatesAt }))
                }
              />
              <TimeControl
                label="Stops applying at (local time, optional)"
                value={assignment.expiresAt}
                onChange={(expiresAt) =>
                  change(create(TargetAssignmentSchema, { ...draft, expiresAt }))
                }
              />
            </div>
            {assignment.exclusions.map((exclusion, index) => (
              <div className="grid gap-2 border p-3" key={index}>
                <TargetControl
                  label={`Exclusion ${index + 1}`}
                  value={exclusion}
                  disabled={frozen || read.isPending}
                  onChange={(next) =>
                    change(
                      create(TargetAssignmentSchema, {
                        ...draft,
                        exclusions: draft.exclusions.map((item, i) => (i === index ? next : item)),
                      }),
                    )
                  }
                />
                <Button
                  type="button"
                  variant="outline"
                  className="w-fit"
                  onClick={() =>
                    change(
                      create(TargetAssignmentSchema, {
                        ...draft,
                        exclusions: draft.exclusions.filter((_, i) => i !== index),
                      }),
                    )
                  }
                >
                  {`Remove exclusion ${index + 1}`}
                </Button>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              className="w-fit"
              onClick={() =>
                change(
                  create(TargetAssignmentSchema, {
                    ...draft,
                    exclusions: [...draft.exclusions, create(TargetRefSchema)],
                  }),
                )
              }
            >
              Add exclusion
            </Button>
            {candidate ? (
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={assignment.disabled}
                  onChange={(event) =>
                    change(
                      create(TargetAssignmentSchema, { ...draft, disabled: event.target.checked }),
                    )
                  }
                />
                Stop this assignment: its devices stop getting these settings
              </label>
            ) : null}
          </div>
        </fieldset>
        {!frozen ? (
          <Button
            type="submit"
            variant={review ? "outline" : "default"}
            className="w-fit"
            disabled={read.isPending}
            data-review-next-action="review-impact"
          >
            {read.isPending
              ? "Reviewing impact…"
              : review
                ? "Review impact again"
                : "Review impact"}
          </Button>
        ) : null}
      </form>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
      {readFailure ? (
        <RpcError failure={readFailure}>
          <p>The console could not review impact. Nothing has changed. Review impact again.</p>
        </RpcError>
      ) : null}
      {evidence ? (
        <>
          <div ref={impact} tabIndex={-1} className="scroll-mt-4 outline-none">
            <AssignmentImpact review={evidence} expired={expired && !frozen} />
          </div>
          {!frozen && (pageAfter || evidence.nextAfterDeviceId) ? (
            <div className="flex flex-wrap gap-2">
              {pageAfter ? (
                <Button
                  type="button"
                  variant="outline"
                  disabled={read.isPending}
                  onClick={() => loadPage("")}
                >
                  First devices
                </Button>
              ) : null}
              {evidence.nextAfterDeviceId ? (
                <Button
                  type="button"
                  variant="outline"
                  disabled={read.isPending}
                  onClick={() => loadPage(evidence.nextAfterDeviceId)}
                >
                  More devices
                </Button>
              ) : null}
            </div>
          ) : null}
          <form
            className="grid gap-3 border-t pt-4"
            aria-label="Roll out"
            onSubmit={(event) => {
              event.preventDefault();
              rollOut();
            }}
          >
            <fieldset disabled={frozen} className="grid gap-3">
              <ReasonControl
                label="Reason for this rollout"
                value={frozen ? attempt.request.reason : reason}
                onChange={setReason}
              />
            </fieldset>
            {approvalRequired && !settled ? (
              <p className="text-sm">
                Another administrator must approve this rollout. Nothing changes on any device until
                they do.
              </p>
            ) : null}
            {!settled ? (
              <Button
                type="submit"
                className="w-fit"
                data-review-next-action="roll-out"
                disabled={
                  busy ||
                  (!attempt &&
                    (!evidence.complete ||
                      expired ||
                      !reason.trim() ||
                      !rolloutName.trim() ||
                      !!problem ||
                      read.isPending ||
                      !!readFailure))
                }
              >
                {attempt?.phase === "starting"
                  ? "Rolling out…"
                  : attempt?.phase === "requesting"
                    ? "Requesting approval…"
                    : attempt?.phase === "start-ambiguous"
                      ? "Retry the same rollout"
                      : attempt?.phase === "request-failed"
                        ? "Request approval again"
                        : approvalRequired
                          ? "Request approval to roll out"
                          : "Roll out"}
              </Button>
            ) : null}
          </form>
        </>
      ) : null}
      {attempt?.failure ? (
        <RpcError failure={attempt.failure}>
          <p>
            {attempt.phase === "start-ambiguous"
              ? "The server did not confirm the rollout started. Retry the same rollout. The same request cannot start it twice."
              : attempt.phase === "request-failed"
                ? "The rollout needs approval. The server did not confirm the approval request. Retry the same request."
                : (startRefusals[attempt.failure.reason] ??
                  "The rollout did not start. Nothing changed. Review impact again.")}
          </p>
        </RpcError>
      ) : null}
      {attempt?.phase === "awaiting" ? (
        <div role="status" className="grid gap-2 border bg-muted/30 p-3 text-sm">
          <p className="font-medium">Waiting for approval from another administrator</p>
          <p>
            Nothing changes until they approve. Then the rollout starts within a minute. Without a
            decision, the request expires in an hour.
          </p>
          <Link to="/approvals" className="w-fit underline underline-offset-4">
            Open Approvals
          </Link>
        </div>
      ) : null}
      {attempt?.phase === "started" ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm">
          Rolling out to {attempt.rollout?.plannedCount ?? 0}{" "}
          {attempt.rollout?.plannedCount === 1 ? "device" : "devices"}. Follow its progress in the
          list.
        </p>
      ) : null}
      {settled ? (
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            onClick={() => {
              update(key);
              onClose();
            }}
          >
            Done
          </Button>
        </div>
      ) : null}
    </div>
  );
}
