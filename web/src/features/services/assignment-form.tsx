import { create, createRegistry, getOption } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { field as validationRules } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
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
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { setAssignmentAttempt, useAssignmentAttempt, type AssignmentAttempt } from "./attempt";
import { resourceProfileHeadsQueryOptions, resourceStateQueryOptions } from "./queries";

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
}: {
  deviceId: string;
  expectedAssignmentId: string | undefined;
  stateReady: boolean;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const attempt = useAssignmentAttempt(deviceId);
  const inFlight = useRef(false);
  const [pageToken, setPageToken] = useState("");
  const heads = useQuery(resourceProfileHeadsQueryOptions(lifetime, pageToken));
  const [revisionId, setRevisionId] = useState("");
  const [reason, setReason] = useState("");
  const [intervalSeconds, setIntervalSeconds] = useState(defaultIntervalSeconds);
  const [requestId, setRequestId] = useState(newRequestId);
  const [errors, setErrors] = useState<string[]>([]);
  const [rpcFailure, setRpcFailure] = useState<RpcFailure | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [approvalRequired, setApprovalRequired] = useState(
    attempt?.failure?.message === "approval_required",
  );
  const [approvalBusy, setApprovalBusy] = useState(false);
  const [approvalId, setApprovalId] = useState("");
  const [approvalAmbiguous, setApprovalAmbiguous] = useState(false);
  const locked = attempt !== null || refreshing;
  const headFailure = heads.error ? toRpcFailure(heads.error) : null;

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
      setApprovalRequired(
        rpcError.metadata.get("lindm-reason") === "approval_required" ||
          rpcError.rawMessage === "approval_required",
      );
      const conflict =
        rpcError.metadata.get("lindm-reason") === "resource_assignment_conflict" ||
        rpcError.rawMessage === "resource_assignment_conflict";
      const failure = conflict ? { ...normalized, ambiguous: false } : normalized;
      setAssignmentAttempt(lifetime, deviceId, {
        ...captured,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        failure,
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
      !setAssignmentAttempt(lifetime, deviceId, { ...captured, status: "inflight", failure: null })
    )
      return;
    inFlight.current = true;
    mutation.mutate(captured);
  }

  function capture(clear: boolean) {
    if (locked || !stateReady) return;
    const head = heads.data?.profiles.find((profile) => profile.revisionId === revisionId);
    if (!clear && (!head || headFailure)) {
      setErrors(["Select a profile."]);
      return;
    }
    const payload = create(SetResourceAssignmentRequestSchema, {
      requestId,
      deviceId,
      expectedAssignmentId,
      clear,
      reason: reason.trim(),
      target: clear ? undefined : { profileId: head!.profileId, revisionId: head!.revisionId },
      reconcileIntervalSeconds: clear ? undefined : Number(intervalSeconds),
    });
    const validation = validator.validate(SetResourceAssignmentRequestSchema, payload);
    if (validation.kind !== "valid") {
      setErrors(
        validation.kind === "invalid"
          ? validation.violations.map((violation) => violation.toString())
          : [`Assignment validation failed: ${validation.error.message}`],
      );
      return;
    }
    setErrors([]);
    send({
      payload,
      targetLabel: clear
        ? "Remove profile"
        : `${head!.name}, version ${head!.revisionNumber.toString()}`,
      status: "inflight",
      failure: null,
    });
  }

  async function requestApproval() {
    if (!attempt || approvalBusy || lifetime.signal.aborted) return;
    setApprovalBusy(true);
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
      setApprovalId(result.approval?.id ?? "");
      setApprovalAmbiguous(false);
      toast.success("Approval requested");
      await queryClient.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const failure = toRpcFailure(error);
        setApprovalAmbiguous(failure.ambiguous);
        setRpcFailure(failure);
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
    } finally {
      if (!lifetime.signal.aborted) setApprovalBusy(false);
    }
  }

  async function prepareAnother() {
    if (
      inFlight.current ||
      refreshing ||
      attempt?.status === "ambiguous" ||
      attempt?.status === "inflight"
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
      setApprovalRequired(false);
      setApprovalId("");
      setApprovalAmbiguous(false);
      setReason("");
      setRevisionId("");
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
          <Label htmlFor="resource-profile">Profile version</Label>
          <SelectField
            id="resource-profile"
            className="h-9 w-full min-w-0"
            value={revisionId}
            disabled={locked || heads.isPending || !!headFailure}
            onValueChange={(value) => setRevisionId(value)}
            options={[
              { value: "", label: "Select a profile" },
              ...(heads.data?.profiles.map((profile) => ({
                value: profile.revisionId,
                label: `${profile.name}, version ${profile.revisionNumber.toString()}`,
              })) ?? []),
            ]}
          />
          {heads.isPending ? (
            <p role="status" className="text-sm text-muted-foreground">
              Loading profiles…
            </p>
          ) : null}
          {heads.data?.profiles.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No profiles found. Create one under Profiles.
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            {pageToken ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={locked || heads.isFetching}
                onClick={() => {
                  setPageToken("");
                  setRevisionId("");
                }}
              >
                First profile page
              </Button>
            ) : null}
            {heads.data?.nextPageToken ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={locked || heads.isFetching}
                onClick={() => {
                  setPageToken(heads.data!.nextPageToken);
                  setRevisionId("");
                }}
              >
                Next profile page
              </Button>
            ) : null}
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={locked || heads.isFetching}
              onClick={() => void heads.refetch()}
            >
              Refresh profiles
            </Button>
          </div>
          {headFailure ? <RpcError failure={headFailure} title="Couldn't load profiles" /> : null}
        </div>
      )}
      <div className="grid min-w-0 gap-2">
        <Label htmlFor="service-reconcile-interval">Check interval (seconds)</Label>
        <Input
          id="service-reconcile-interval"
          type="number"
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
      {approvalRequired ? (
        <div className="grid gap-3 border bg-muted/30 p-4 text-sm">
          <p>This change needs approval from another administrator.</p>
          {approvalId ? (
            <p>
              Approval requested.{" "}
              <Link to="/approvals" className="underline">
                Open approvals
              </Link>
            </p>
          ) : (
            <Button type="button" disabled={approvalBusy} onClick={() => void requestApproval()}>
              {approvalBusy
                ? "Requesting approval…"
                : approvalAmbiguous
                  ? "Retry approval request"
                  : "Request approval"}
            </Button>
          )}
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
          { label: "Approval ID", value: approvalId },
        ]}
      />
      <div className="flex flex-wrap gap-2">
        {!attempt ? (
          <>
            <Button type="submit" disabled={!stateReady || locked || !revisionId || !!headFailure}>
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
            disabled={refreshing || approvalBusy || approvalAmbiguous || approvalId !== ""}
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
}: {
  deviceId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const lifetime = useAuthLifetime();
  const state = useQuery(resourceStateQueryOptions(lifetime, deviceId));
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
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
        />
      </DialogContent>
    </Dialog>
  );
}
