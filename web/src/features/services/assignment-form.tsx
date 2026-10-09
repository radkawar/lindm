import { create, createRegistry } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { SetServiceAssignmentRequestSchema } from "../../../gen/lindm/admin/v1/service_assignments_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { setAssignmentAttempt, useAssignmentAttempt, type AssignmentAttempt } from "./attempt";
import { serviceProfileHeadsQueryOptions, serviceStateQueryOptions } from "./queries";

const validator = createValidator({ registry: createRegistry(audit_reason) });

export function ServiceAssignmentForm({
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
  const heads = useQuery(serviceProfileHeadsQueryOptions(lifetime, pageToken));
  const [revisionId, setRevisionId] = useState("");
  const [reason, setReason] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [errors, setErrors] = useState<string[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const locked = attempt !== null || refreshing;
  const headFailure = heads.error ? toRpcFailure(heads.error) : null;

  const mutation = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (captured: AssignmentAttempt) => {
      const response = await adminClient.setServiceAssignment(captured.payload, {
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
      void queryClient.invalidateQueries({
        queryKey: serviceStateQueryOptions(lifetime, deviceId).queryKey,
        exact: true,
      });
    },
    onError: (error, captured) => {
      const normalized = toRpcFailure(error);
      const rpcError = ConnectError.from(error);
      const conflict =
        rpcError.metadata.get("lindm-reason") === "service_assignment_conflict" ||
        rpcError.rawMessage === "service_assignment_conflict";
      const failure = conflict ? { ...normalized, ambiguous: false } : normalized;
      setAssignmentAttempt(lifetime, deviceId, {
        ...captured,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        failure,
      });
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
      setErrors(["Select a loaded profile revision before assigning."]);
      return;
    }
    const payload = create(SetServiceAssignmentRequestSchema, {
      requestId,
      deviceId,
      expectedAssignmentId,
      clear,
      reason: reason.trim(),
      target: clear ? undefined : { profileId: head!.profileId, revisionId: head!.revisionId },
    });
    const validation = validator.validate(SetServiceAssignmentRequestSchema, payload);
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
        ? "Stop managing"
        : `${head!.name} · revision ${head!.revisionNumber.toString()}`,
      status: "inflight",
      failure: null,
    });
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
    try {
      await queryClient.fetchQuery(serviceStateQueryOptions(lifetime, deviceId));
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      setAssignmentAttempt(lifetime, deviceId, null);
      setRequestId(newRequestId());
      setReason("");
      setRevisionId("");
    } catch (error) {
      if (getAuthLifetime() === lifetime && !lifetime.signal.aborted)
        setErrors([toRpcFailure(error).message]);
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <form
      className="grid gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        capture(false);
      }}
    >
      <h3 className="font-semibold">Assign a profile revision</h3>
      <p className="text-sm text-muted-foreground">
        Assigning pins all resources to the selected catalog head. Later profile publications do not
        change this assignment. Stop managing stops new work; it does not revert services or cancel
        already authorized effects.
      </p>
      {attempt ? (
        <p className="text-sm">
          Captured request: {attempt.targetLabel}. The request stays frozen across navigation until
          its outcome is resolved. Reloading the tab clears this local retry record.
        </p>
      ) : (
        <>
          <Label htmlFor="service-profile">Profile revision</Label>
          <select
            id="service-profile"
            className="h-9 w-full rounded-lg border border-input bg-background px-2 text-sm"
            value={revisionId}
            disabled={locked || heads.isPending || !!headFailure}
            onChange={(event) => setRevisionId(event.target.value)}
          >
            <option value="">Select a profile head</option>
            {heads.data?.profiles.map((profile) => (
              <option key={profile.revisionId} value={profile.revisionId}>
                {profile.name} · revision {profile.revisionNumber.toString()}
              </option>
            ))}
          </select>
          {heads.isPending ? <p role="status">Loading profile heads…</p> : null}
          {heads.data?.profiles.length === 0 ? (
            <p className="text-sm">No profile heads on this page.</p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            {pageToken ? (
              <Button
                type="button"
                variant="outline"
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
              disabled={locked || heads.isFetching}
              onClick={() => void heads.refetch()}
            >
              Refresh profiles
            </Button>
          </div>
          {headFailure ? (
            <Alert variant="destructive">
              <AlertTitle>Profile heads unavailable</AlertTitle>
              <AlertDescription>
                {headFailure.codeName}: {headFailure.message}
              </AlertDescription>
            </Alert>
          ) : null}
        </>
      )}
      <Label htmlFor="service-assignment-reason">Reason (required)</Label>
      <Textarea
        id="service-assignment-reason"
        required
        readOnly={locked}
        value={attempt?.payload.reason ?? reason}
        onChange={(event) => setReason(event.target.value)}
      />
      <p className="break-all font-mono text-xs text-muted-foreground">
        Request ID {attempt?.payload.requestId ?? requestId}
      </p>
      <p className="break-all font-mono text-xs text-muted-foreground">
        Expected assignment:{" "}
        {(attempt ? attempt.payload.expectedAssignmentId : expectedAssignmentId) ??
          "none (never assigned)"}
      </p>
      {errors.length ? (
        <Alert variant="destructive">
          <AlertTitle>Cannot prepare assignment</AlertTitle>
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
        <Alert variant="destructive">
          <AlertTitle>
            {attempt.status === "ambiguous"
              ? "Assignment outcome unknown"
              : attempt.failure.denied
                ? "Not authorized to assign services"
                : "Assignment rejected"}
          </AlertTitle>
          <AlertDescription>
            {attempt.failure.codeName}: {attempt.failure.message}
            {attempt.status === "ambiguous"
              ? " Retry the exact request; do not send a replacement."
              : " Refresh the assignment before preparing a new request."}
          </AlertDescription>
        </Alert>
      ) : null}
      {attempt?.status === "succeeded" ? (
        <p role="status">
          Assignment accepted. The current state is refreshed separately; this receipt does not
          imply native execution.
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {!attempt ? (
          <>
            <Button type="submit" disabled={!stateReady || locked || !revisionId || !!headFailure}>
              Assign selected revision
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!stateReady || locked || expectedAssignmentId === undefined}
              onClick={() => capture(true)}
            >
              Stop managing
            </Button>
          </>
        ) : null}
        {attempt?.status === "inflight" ? <p role="status">Sending assignment…</p> : null}
        {attempt?.status === "ambiguous" ? (
          <Button type="button" onClick={() => send(attempt)}>
            Retry exact request
          </Button>
        ) : null}
        {attempt?.status === "rejected" || attempt?.status === "succeeded" ? (
          <Button
            type="button"
            variant="outline"
            disabled={refreshing}
            onClick={() => void prepareAnother()}
          >
            {refreshing ? "Refreshing assignment…" : "Refresh and prepare another request"}
          </Button>
        ) : null}
      </div>
    </form>
  );
}
