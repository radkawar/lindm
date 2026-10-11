import { create, createRegistry } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { createValidator } from "@bufbuild/protovalidate";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, useSyncExternalStore } from "react";
import { toast } from "sonner";
import {
  PreviewTargetAssignmentImpactRequestSchema,
  SaveTargetAssignmentImpactRequestSchema,
  type PreviewTargetAssignmentImpactResponse,
  type PreviewTargetAssignmentImpactRequest,
  type SaveTargetAssignmentImpactRequest,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import {
  TargetAssignmentSchema,
  TargetRefSchema,
  type TargetCandidate,
} from "../../../gen/lindm/policy/v1/targeting_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime, subscribeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import {
  CohortControl,
  NumberControl,
  OptionalControls,
  ReasonControl,
  TimeControl,
} from "./controls";
import { RolloutPicker, useTargetPickers } from "./pickers";
import { AssignmentImpact } from "./impact";

const validator = createValidator({ registry: createRegistry(audit_reason) });
type Attempt = {
  request: SaveTargetAssignmentImpactRequest;
  review: PreviewTargetAssignmentImpactResponse;
  status: "pending" | "ambiguous" | "accepted" | "rejected";
  failure?: RpcFailure;
};
const attempts = new Map<string, Attempt>();
const listeners = new Set<() => void>();
function notify() {
  for (const listener of listeners) listener();
}
function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
subscribeAuthLifetime(() => {
  attempts.clear();
  notify();
});

export function AssignmentForm({ candidate }: { candidate?: TargetCandidate }) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const { profileRevisionPicker: ProfileRevisionPicker } = useTargetPickers();
  const key = candidate?.assignment?.assignmentId ?? "new";
  const attempt = useSyncExternalStore(subscribe, () => attempts.get(key));
  const [draft, setDraft] = useState(() =>
    create(TargetAssignmentSchema, candidate?.assignment ?? { assignmentId: newRequestId() }),
  );
  const [review, setReview] = useState<PreviewTargetAssignmentImpactResponse>();
  const [pageAfter, setPageAfter] = useState("");
  const [reason, setReason] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState("");
  const [readFailure, setReadFailure] = useState<RpcFailure>();
  const [now, setNow] = useState(Date.now);
  const evidence = attempt?.status === "rejected" ? review : (attempt?.review ?? review);
  const assignment =
    attempt?.status === "rejected" ? draft : (attempt?.request.assignment ?? draft);
  const expectedRevision = candidate?.revision ?? 0n;
  const frozen = !!attempt && attempt.status !== "rejected";
  const ProposalContainer = frozen ? "section" : "form";
  const ConfirmationContainer = attempt?.status === "accepted" ? "section" : "form";
  const expired =
    !!evidence && (!evidence.validUntil || timestampDate(evidence.validUntil).getTime() <= now);
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
        throw new Error("The impact review was incomplete. Review again before saving.");
      return result;
    },
    onSuccess: (result, request) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      setReview(result);
      setReadFailure(undefined);
      setNow(Date.now());
      setPageAfter(request.afterDeviceId ?? "");
    },
    onError: (cause) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      setReadFailure(toRpcFailure(cause));
    },
  });
  const save = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: SaveTargetAssignmentImpactRequest) => {
      const result = await adminClient.saveTargetAssignmentImpact(request, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      return result;
    },
    onSuccess: () => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      const current = attempts.get(key);
      if (current) attempts.set(key, { ...current, status: "accepted", failure: undefined });
      notify();
      toast.success("Assignment saved", { description: "No device changes were activated." });
      void client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
    },
    onError: (cause) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      const current = attempts.get(key);
      const failure = toRpcFailure(cause);
      if (current)
        attempts.set(key, {
          ...current,
          status: failure.ambiguous ? "ambiguous" : "rejected",
          failure,
        });
      if (!failure.ambiguous) {
        setReview(undefined);
        setAcknowledged(false);
      }
      notify();
    },
  });
  function change(next: typeof draft) {
    setDraft(next);
    setReview(undefined);
    setAcknowledged(false);
    setReadFailure(undefined);
    setError("");
    if (attempt?.status === "rejected") {
      attempts.delete(key);
      notify();
    }
  }
  function loadPage(afterDeviceId?: string) {
    if (frozen || read.isPending) return;
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
        result.kind === "invalid"
          ? result.violations.map((item) => item.toString()).join("; ")
          : result.error.message,
      );
      return;
    }
    if (afterDeviceId === undefined) {
      setReview(undefined);
      setAcknowledged(false);
      setPageAfter("");
    }
    if (attempt?.status === "rejected") {
      attempts.delete(key);
      notify();
    }
    setReadFailure(undefined);
    setError("");
    read.mutate(request);
  }
  return (
    <section
      className="grid min-w-0 gap-4"
      data-review-state={
        attempt?.status ??
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
      <ProposalContainer
        className="grid min-w-0 gap-4"
        aria-label="Assignment proposal"
        onSubmit={(event) => {
          event.preventDefault();
          loadPage();
        }}
      >
        <fieldset disabled={frozen || read.isPending} className="grid min-w-0 gap-4">
          <div className="grid min-w-0 gap-4 sm:grid-cols-2">
            <CohortControl
              label="Cohort"
              value={assignment.target}
              disabled={frozen || read.isPending}
              onChange={(target) => change(create(TargetAssignmentSchema, { ...draft, target }))}
            />
            <ProfileRevisionPicker
              label="Baseline revision"
              value={assignment.profileRevisionId}
              disabled={frozen || read.isPending}
              onChange={(profileRevisionId) =>
                change(create(TargetAssignmentSchema, { ...draft, profileRevisionId }))
              }
            />
          </div>
          <OptionalControls title="Timing, exclusions and priority">
            <NumberControl
              label="Assignment priority"
              value={assignment.priority}
              onChange={(priority) =>
                change(create(TargetAssignmentSchema, { ...draft, priority }))
              }
            />
            <p className="text-sm text-muted-foreground">
              Higher priority wins where settings overlap. Equal priority can conflict.
            </p>
            <RolloutPicker
              label="Optional staged rollout"
              value={assignment.rolloutId ?? ""}
              disabled={frozen || read.isPending}
              onChange={(rolloutId) =>
                change(
                  create(TargetAssignmentSchema, { ...draft, rolloutId: rolloutId || undefined }),
                )
              }
            />
            <div className="grid gap-3 sm:grid-cols-2">
              <TimeControl
                label="Eligible from (local time, optional)"
                value={assignment.activatesAt}
                onChange={(activatesAt) =>
                  change(create(TargetAssignmentSchema, { ...draft, activatesAt }))
                }
              />
              <TimeControl
                label="Expires at (local time, optional)"
                value={assignment.expiresAt}
                onChange={(expiresAt) =>
                  change(create(TargetAssignmentSchema, { ...draft, expiresAt }))
                }
              />
            </div>
            {assignment.exclusions.map((exclusion, index) => (
              <div className="grid gap-2 border p-3" key={index}>
                <CohortControl
                  label={`Exclude ${index + 1}`}
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
                  onClick={() =>
                    change(
                      create(TargetAssignmentSchema, {
                        ...draft,
                        exclusions: draft.exclusions.filter((_, i) => i !== index),
                      }),
                    )
                  }
                >
                  Remove exclusion {index + 1}
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
              Disable this assignment, keeping its history
            </label>
          </OptionalControls>
        </fieldset>
        {!frozen ? (
          <Button
            type="submit"
            className="w-fit"
            disabled={read.isPending}
            data-review-next-action="review-impact"
          >
            {read.isPending ? "Reviewing affected devices…" : "Review affected devices"}
          </Button>
        ) : null}
      </ProposalContainer>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
      {readFailure ? (
        <RpcError failure={readFailure}>
          <p>Impact could not be confirmed. Review again; nothing has been saved.</p>
        </RpcError>
      ) : null}
      {evidence && attempt?.status !== "rejected" ? (
        <>
          <AssignmentImpact review={evidence} expired={expired} />
          {pageAfter && !frozen ? (
            <Button
              type="button"
              variant="outline"
              className="w-fit"
              disabled={read.isPending}
              onClick={() => loadPage("")}
            >
              First affected devices
            </Button>
          ) : null}
          {evidence.nextAfterDeviceId && !frozen ? (
            <Button
              type="button"
              variant="outline"
              className="w-fit"
              disabled={read.isPending}
              onClick={() => loadPage(evidence.nextAfterDeviceId)}
            >
              More affected devices
            </Button>
          ) : null}
          <ConfirmationContainer
            className="grid gap-3 border-t pt-4"
            aria-label="Assignment confirmation"
            onSubmit={(event) => {
              event.preventDefault();
              if (attempt && attempt.status !== "ambiguous") return;
              if (
                !attempt &&
                (!review ||
                  !review.complete ||
                  expired ||
                  !acknowledged ||
                  !reason.trim() ||
                  read.isPending ||
                  readFailure)
              )
                return;
              const request =
                attempt?.request ??
                create(SaveTargetAssignmentImpactRequestSchema, {
                  requestId: newRequestId(),
                  previewId: evidence.previewId,
                  reviewSha256: evidence.reviewSha256,
                  assignment: evidence.assignment,
                  expectedRevision: evidence.expectedRevision,
                  reason,
                });
              const result = validator.validate(SaveTargetAssignmentImpactRequestSchema, request);
              if (result.kind !== "valid") {
                setError(
                  result.kind === "invalid"
                    ? result.violations.map((item) => item.toString()).join("; ")
                    : result.error.message,
                );
                return;
              }
              attempts.set(key, { request, review: evidence, status: "pending" });
              notify();
              setError("");
              save.mutate(request);
            }}
          >
            <p className="text-sm">
              Saving records this assignment only. To change a device, separately inspect its saved
              settings and activate the exact approved preview.
            </p>
            <fieldset disabled={frozen} className="grid gap-3">
              <ReasonControl
                label="Reason for this assignment"
                value={attempt?.request.reason ?? reason}
                onChange={setReason}
              />
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={acknowledged || !!attempt}
                  onChange={(event) => setAcknowledged(event.target.checked)}
                />
                I reviewed the affected devices and consequences
              </label>
            </fieldset>
            {attempt?.status !== "accepted" ? (
              <Button
                type="submit"
                className="w-fit"
                data-review-next-action="save-assignment"
                disabled={
                  attempt?.status === "pending" ||
                  (!attempt &&
                    (!evidence.complete ||
                      expired ||
                      !acknowledged ||
                      !reason.trim() ||
                      read.isPending ||
                      !!readFailure))
                }
              >
                {attempt?.status === "pending"
                  ? "Saving assignment…"
                  : attempt?.status === "ambiguous"
                    ? "Retry exact save"
                    : "Save reviewed assignment"}
              </Button>
            ) : null}
          </ConfirmationContainer>
        </>
      ) : null}
      {attempt?.failure ? (
        <RpcError failure={attempt.failure}>
          <p>
            {attempt.status === "ambiguous"
              ? "The save outcome is unknown. Retry the same reviewed request; do not create another assignment."
              : "The assignment was not saved. Refresh saved assignments if another administrator edited it, then review the current impact again."}
          </p>
        </RpcError>
      ) : null}
      {attempt?.status === "accepted" ? (
        <div role="status" className="grid gap-3 text-sm">
          <p>Assignment saved. No device changes were activated.</p>
          <Button
            type="button"
            variant="outline"
            className="w-fit"
            onClick={() => {
              attempts.delete(key);
              notify();
              setDraft(
                create(
                  TargetAssignmentSchema,
                  candidate?.assignment ?? { assignmentId: newRequestId() },
                ),
              );
              setReview(undefined);
              setReason("");
              setAcknowledged(false);
            }}
          >
            {candidate ? "Review another change" : "Assign another baseline"}
          </Button>
        </div>
      ) : null}
    </section>
  );
}
