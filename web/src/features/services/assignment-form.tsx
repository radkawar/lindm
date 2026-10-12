import { create, createRegistry, getOption } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { field as validationRules } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { SetResourceAssignmentRequestSchema } from "../../../gen/lindm/admin/v1/assignments_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import type { PickerProps } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { describeViolation } from "@/lib/validation";
import {
  setAssignmentApproval,
  setAssignmentAttempt,
  useAssignmentAttempt,
  type AssignmentAttempt,
} from "./attempt";
import { resourceStateQueryOptions } from "./queries";

export type ProfileChoice = { profileId: string; revisionId: string; label: string };
// Composed by the route: chooses a profile by name and reports its latest version.
export type ProfileChoiceSlot = (
  props: PickerProps & { onChoose: (choice: ProfileChoice | null) => void },
) => ReactNode;

const validator = createValidator({ registry: createRegistry(audit_reason) });
const intervalRules = getOption(
  SetResourceAssignmentRequestSchema.field.reconcileIntervalSeconds,
  validationRules,
).type;
if (
  intervalRules.case !== "uint32" ||
  intervalRules.value.greaterThan.case !== "gte" ||
  intervalRules.value.lessThan.case !== "lte"
) {
  throw new Error("Missing bounded reconciliation interval constraint");
}
const intervalMin = intervalRules.value.greaterThan.value;
const intervalMax = intervalRules.value.lessThan.value;
const defaultIntervalSeconds = "900";

export function ResourceAssignmentForm({
  deviceId,
  expectedAssignmentId,
  stateReady,
  profilePicker: ProfileChoicePicker,
}: {
  deviceId: string;
  expectedAssignmentId: string | undefined;
  stateReady: boolean;
  profilePicker: ProfileChoiceSlot;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const attempt = useAssignmentAttempt(deviceId);
  const inFlight = useRef(false);
  const [profileId, setProfileId] = useState("");
  const [choice, setChoice] = useState<ProfileChoice | null>(null);
  const [reason, setReason] = useState("");
  const [intervalSeconds, setIntervalSeconds] = useState(defaultIntervalSeconds);
  const [requestId, setRequestId] = useState(newRequestId);
  const [errors, setErrors] = useState<string[]>([]);
  const [rpcFailure, setRpcFailure] = useState<RpcFailure | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const approval = attempt?.approval ?? null;
  const locked = attempt !== null || refreshing;

  const mutation = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (captured: AssignmentAttempt) => {
      const response = await adminClient.setResourceAssignment(captured.payload, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      if (!response.assignment?.assignmentId) {
        throw new Error("The server did not return an assignment receipt.");
      }
      return response.assignment;
    },
    onSuccess: (_assignment, captured) => {
      if (
        !setAssignmentAttempt(lifetime, deviceId, {
          ...captured,
          status: "succeeded",
          failure: null,
        })
      )
        return;
      toast.success("Assignment saved", {
        description: "The device applies it at its next check-in.",
      });
      void queryClient.invalidateQueries({
        queryKey: resourceStateQueryOptions(lifetime, deviceId).queryKey,
        exact: true,
      });
    },
    onError: (error, captured) => {
      const normalized = toRpcFailure(error);
      const rpcError = ConnectError.from(error);
      const approvalRequired =
        rpcError.metadata.get("lindm-reason") === "approval_required" ||
        rpcError.rawMessage === "approval_required";
      const conflict =
        rpcError.metadata.get("lindm-reason") === "resource_assignment_conflict" ||
        rpcError.rawMessage === "resource_assignment_conflict";
      const failure = conflict ? { ...normalized, ambiguous: false } : normalized;
      setAssignmentAttempt(lifetime, deviceId, {
        ...captured,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        failure,
        approval: approvalRequired ? { status: "needed", approvalId: "", failure: null } : null,
      });
      if (!lifetime.signal.aborted) {
        toast[
          classifyRpcFailure(failure).tone === "destructive"
            ? "error"
            : classifyRpcFailure(failure).tone === "warning"
              ? "warning"
              : "message"
        ](failure.ambiguous ? "Couldn't confirm the assignment" : "Assignment not saved", {
          description: "Open Assign profile to see what happened.",
        });
      }
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });

  function send(captured: AssignmentAttempt) {
    if (inFlight.current || attempt?.status === "inflight") return;
    if (
      !setAssignmentAttempt(lifetime, deviceId, {
        ...captured,
        status: "inflight",
        failure: null,
        approval: null,
      })
    )
      return;
    inFlight.current = true;
    mutation.mutate(captured);
  }

  function capture(clear: boolean) {
    if (locked || !stateReady) return;
    if (!clear && !choice) {
      setErrors(["Choose a profile."]);
      return;
    }
    const payload = create(SetResourceAssignmentRequestSchema, {
      requestId,
      deviceId,
      expectedAssignmentId,
      clear,
      reason: reason.trim(),
      target: clear ? undefined : { profileId: choice!.profileId, revisionId: choice!.revisionId },
      reconcileIntervalSeconds: clear ? undefined : Number(intervalSeconds),
    });
    const validation = validator.validate(SetResourceAssignmentRequestSchema, payload);
    if (validation.kind !== "valid") {
      setErrors(
        validation.kind === "invalid"
          ? validation.violations.map((violation) => describeViolation(violation).message)
          : [`Assignment validation failed: ${validation.error.message}`],
      );
      return;
    }
    setErrors([]);
    send({
      payload,
      targetLabel: clear ? "Remove profile" : choice!.label,
      status: "inflight",
      failure: null,
      approval: null,
    });
  }

  async function requestApproval() {
    if (!attempt || !approval || lifetime.signal.aborted) return;
    if (approval.status === "inflight" || approval.status === "requested") return;
    if (
      !setAssignmentApproval(lifetime, deviceId, {
        status: "inflight",
        approvalId: "",
        failure: null,
      })
    )
      return;
    setErrors([]);
    setRpcFailure(null);
    try {
      const result = await adminClient.createApproval(
        {
          lifetimeSeconds: 3600,
          payload: { case: "setResourceAssignment", value: attempt.payload },
        },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      setAssignmentApproval(lifetime, deviceId, {
        status: "requested",
        approvalId: result.approval?.id ?? "",
        failure: null,
      });
      toast.success("Approval requested");
      await queryClient.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const failure = toRpcFailure(error);
        setAssignmentApproval(lifetime, deviceId, {
          status: failure.ambiguous ? "ambiguous" : "failed",
          approvalId: "",
          failure,
        });
        toast[
          classifyRpcFailure(failure).tone === "destructive"
            ? "error"
            : classifyRpcFailure(failure).tone === "warning"
              ? "warning"
              : "message"
        ](failure.ambiguous ? "Couldn't confirm the approval request" : "Approval request failed", {
          description: "Open Assign profile to see what happened.",
        });
      }
    }
  }

  async function prepareAnother() {
    if (
      inFlight.current ||
      refreshing ||
      attempt?.status === "ambiguous" ||
      attempt?.status === "inflight" ||
      approval?.status === "inflight"
    )
      return;
    setRefreshing(true);
    setErrors([]);
    setRpcFailure(null);
    try {
      await queryClient.fetchQuery(resourceStateQueryOptions(lifetime, deviceId));
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      setAssignmentAttempt(lifetime, deviceId, null);
      setRequestId(newRequestId());
      setReason("");
      setProfileId("");
      setChoice(null);
      setIntervalSeconds(defaultIntervalSeconds);
    } catch (error) {
      if (getAuthLifetime() === lifetime && !lifetime.signal.aborted)
        setRpcFailure(toRpcFailure(error));
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <form
      className="grid min-w-0 gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        capture(false);
      }}
    >
      {attempt ? (
        <p className="border bg-muted/30 p-3 text-sm">
          {attempt.payload.clear ? "Removing the profile" : `Assigning ${attempt.targetLabel}`}
        </p>
      ) : (
        <div className="grid min-w-0 gap-2">
          <ProfileChoicePicker
            label="Profile"
            value={profileId}
            disabled={locked}
            onChange={setProfileId}
            onChoose={setChoice}
          />
          {choice ? (
            <p className="text-sm text-muted-foreground">
              Assigns the latest version: {choice.label}.
            </p>
          ) : null}
          <input type="hidden" name="profile-revision-id" value={choice?.revisionId ?? ""} />
        </div>
      )}
      <div className="grid min-w-0 gap-2">
        <Label htmlFor="service-reconcile-interval">Check interval (seconds)</Label>
        <Input
          id="service-reconcile-interval"
          type="number"
          data-freeform="numeric check interval"
          className="h-9"
          min={intervalMin}
          max={intervalMax}
          step={1}
          required={!attempt?.payload.clear}
          readOnly={locked}
          disabled={attempt?.payload.clear}
          value={attempt ? (attempt.payload.reconcileIntervalSeconds ?? "") : intervalSeconds}
          onChange={(event) => setIntervalSeconds(event.target.value)}
          aria-describedby="service-reconcile-interval-help"
        />
        <p id="service-reconcile-interval-help" className="text-sm text-muted-foreground">
          How often the device checks the profile and fixes drift. Default 900 (15 minutes), between{" "}
          {intervalMin} and {intervalMax}.
        </p>
      </div>
      <div className="grid min-w-0 gap-2">
        <Label htmlFor="service-assignment-reason">Reason (required)</Label>
        <Textarea
          id="service-assignment-reason"
          data-freeform="audit reason"
          required
          readOnly={locked}
          value={attempt?.payload.reason ?? reason}
          onChange={(event) => setReason(event.target.value)}
        />
      </div>
      {rpcFailure ? <RpcError failure={rpcFailure} /> : null}
      {errors.length ? (
        <Alert variant="destructive">
          <AlertTitle>Check the form</AlertTitle>
          <AlertDescription>
            <ul>
              {errors.map((error, index) => (
                <li key={index}>{error}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}
      {attempt?.failure ? (
        <RpcError failure={attempt.failure}>
          <p>
            {attempt.status === "ambiguous"
              ? "Select Retry to resend the same request. It won't be applied twice."
              : "Start a new assignment to try again."}
          </p>
        </RpcError>
      ) : null}
      {attempt?.status === "succeeded" ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm">
          Assignment saved. The device applies it at its next check-in; results appear under
          Services.
        </p>
      ) : null}
      {approval ? (
        <div className="grid gap-3 border bg-muted/30 p-4 text-sm">
          <p>This change needs approval from another administrator.</p>
          {approval.status === "requested" ? (
            <p>
              Approval requested.{" "}
              <Link to="/approvals" className="underline">
                Open approvals
              </Link>
            </p>
          ) : (
            <Button
              type="button"
              disabled={approval.status === "inflight"}
              onClick={() => void requestApproval()}
            >
              {approval.status === "inflight"
                ? "Requesting approval…"
                : approval.status === "ambiguous"
                  ? "Retry approval request"
                  : "Request approval"}
            </Button>
          )}
          {approval.failure ? <RpcError failure={approval.failure} /> : null}
        </div>
      ) : null}
      <TechnicalDetails
        items={[
          { label: "Request ID", value: attempt?.payload.requestId ?? requestId },
          {
            label: "Replaces assignment",
            value:
              (attempt ? attempt.payload.expectedAssignmentId : expectedAssignmentId) ?? "None",
          },
          { label: "Approval ID", value: approval?.approvalId ?? "" },
        ]}
      />
      <div className="flex flex-wrap gap-2">
        {!attempt ? (
          <>
            <Button type="submit" disabled={!stateReady || locked || !choice}>
              Save assignment
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!stateReady || locked || expectedAssignmentId === undefined}
              onClick={() => capture(true)}
            >
              Remove profile
            </Button>
          </>
        ) : null}
        {attempt?.status === "inflight" ? (
          <p role="status" className="text-sm text-muted-foreground">
            Saving…
          </p>
        ) : null}
        {attempt?.status === "ambiguous" ? (
          <Button type="button" onClick={() => send(attempt)}>
            Retry
          </Button>
        ) : null}
        {attempt?.status === "rejected" || attempt?.status === "succeeded" ? (
          <Button
            type="button"
            variant="outline"
            disabled={
              refreshing ||
              approval?.status === "inflight" ||
              approval?.status === "ambiguous" ||
              approval?.status === "requested"
            }
            onClick={() => void prepareAnother()}
          >
            {refreshing ? "Refreshing…" : "Start a new assignment"}
          </Button>
        ) : null}
      </div>
    </form>
  );
}

export function ResourceAssignmentDialog({
  deviceId,
  open,
  onOpenChange,
  profilePicker,
}: {
  deviceId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  profilePicker: ProfileChoiceSlot;
}) {
  const lifetime = useAuthLifetime();
  const state = useQuery(resourceStateQueryOptions(lifetime, deviceId));
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Assign profile</DialogTitle>
          <DialogDescription>
            Choose the profile this device should follow. Later edits to the profile are not applied
            until you assign the new version.
          </DialogDescription>
        </DialogHeader>
        {state.error ? (
          <RpcError failure={toRpcFailure(state.error)} title="Couldn't load this device" />
        ) : null}
        <ResourceAssignmentForm
          deviceId={deviceId}
          expectedAssignmentId={state.data?.assignment?.assignmentId}
          stateReady={state.isSuccess && !state.error}
          profilePicker={profilePicker}
        />
      </DialogContent>
    </Dialog>
  );
}
